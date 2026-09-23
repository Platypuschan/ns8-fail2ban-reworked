"""Integration with the pinned upstream daemon, socket, database and real action."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
import unittest

from f2bns8.common import atomic_json, database
from f2bns8.engine_config import generate
from f2bns8.node import Node

UPSTREAM = os.getenv("FAIL2BAN_SOURCE")
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(UPSTREAM, "Set FAIL2BAN_SOURCE to the pinned Fail2ban 1.1.1 checkout")
class EngineTests(unittest.TestCase):
    def setUp(self):
        try:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.close()
        except PermissionError:
            if os.getenv("REQUIRE_ENGINE_TEST"):
                raise
            self.skipTest("This execution environment prohibits Unix sockets; CI runs the real daemon test")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.conf = self.root / "config"
        self.node = Node(self.state / "node.sqlite3")
        atomic_json(self.state / "config.json", {"node_name": "ns8-test / fail2ban1", "notifications": {"enabled": True}})
        generate(self.state, self.conf, Path(UPSTREAM) / "config", ROOT / "runtime/ns8_action.py")
        self.env = {**os.environ, "PYTHONPATH": str(ROOT / "imageroot/pypkg") + ":" + UPSTREAM, "F2B_STATE_DIR": str(self.state)}
        self.log = (self.root / "engine.log").open("w+")
        self.process = None
        self.start()

    def start(self):
        self.process = subprocess.Popen([sys.executable, str(Path(UPSTREAM) / "bin/fail2ban-server"), "-c", str(self.conf), "-f", "start"], env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        self.wait_for(lambda: self.command(["status"])[0] == 0)

    def command(self, args):
        if not (self.state / "fail2ban.sock").exists():
            raise FileNotFoundError("Engine socket is not ready")
        sys.path.insert(0, UPSTREAM)
        from fail2ban.client.csocket import CSocket
        client = CSocket(str(self.state / "fail2ban.sock"))
        try:
            return client.send(args)
        finally:
            client.close()

    def wait_for(self, condition):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                if condition():
                    return
            except (OSError, ValueError):
                pass
            if self.process.poll() is not None:
                break
            time.sleep(0.1)
        self.log.flush()
        self.fail("Engine did not reach expected state:\n" + (self.root / "engine.log").read_text())

    def stop(self):
        if self.process and self.process.poll() is None:
            self.command(["stop"])
            self.process.wait(timeout=15)

    def tearDown(self):
        self.stop()
        self.log.close()
        self.temp.cleanup()

    def write_failures(self, count, ip="198.51.100.23"):
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        with (self.state / "logs/sshd.log").open("a") as stream:
            for n in range(count):
                record = json.dumps({"module": "host", "log": "Failed password for root from " + ip + " port " + str(4000+n) + " ssh2"})
                stream.write(stamp + " " + ip + " " + record + "\n")

    def notification_count(self):
        with database(self.node.path) as db:
            return db.execute("SELECT count(*) FROM notifications").fetchone()[0]

    def test_threshold_permanent_ban_original_logs_and_no_restore_notification(self):
        self.assertEqual(self.command(["get", "sshd", "bantime"]), (0, -1))
        self.write_failures(4)
        self.wait_for(lambda: self.command(["status", "sshd"])[1][0][1][1][1] >= 4)
        self.assertEqual(self.node.bans(), [])
        self.assertEqual(self.notification_count(), 0)
        self.write_failures(1)
        self.wait_for(lambda: len(self.node.bans()) == 1)
        self.assertEqual(self.notification_count(), 1)
        event = self.node.pending()[0]
        self.assertEqual(event["module"], "host")
        self.assertEqual(event["matches"].count("Failed password"), 5)
        self.assertEqual(self.command(["get", "sshd", "banip"])[1], ["198.51.100.23"])
        self.stop()
        # Clear only delivery records; permanent ban must survive daemon shutdown.
        with database(self.node.path) as db:
            db.execute("DELETE FROM notifications")
        self.assertEqual(len(self.node.bans()), 1)
        self.start()
        self.wait_for(lambda: bool(self.command(["get", "sshd", "banip"])[1]))
        self.assertEqual(self.notification_count(), 0)
        self.assertEqual(len(self.node.bans()), 1)


if __name__ == "__main__":
    unittest.main()
