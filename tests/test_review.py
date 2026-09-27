"""Regressions for ownership, protocol deltas and hardening."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid
from urllib.error import HTTPError

from f2bns8.actions import configure, validate
from f2bns8.collector import Collector, owns_record, restore_samba_logging, samba_logging
from f2bns8.common import _local_protection, allowed, atomic_json, database
from f2bns8 import lifecycle
from f2bns8.firewall import intact, table_name
from f2bns8.node import Node
from f2bns8.notify import MAX_ATTEMPTS, process_one
from f2bns8.parsers import parse
from f2bns8.queue import drain, enqueue
from f2bns8.registry import Registry
from f2bns8.transport import make_server, request


class OwnershipAndParserTests(unittest.TestCase):
    def test_rootful_samba_and_prefix_collision(self):
        source = {"module": "samba1", "uid": "0", "uid_ranges": [(0, 1)],
                  "containers": {"a" * 64: "samba-dc"}}
        self.assertTrue(owns_record(source, {"_UID": "0", "CONTAINER_NAME": "samba-dc"}))
        self.assertTrue(owns_record(source, {"_UID": "0", "CONTAINER_ID_FULL": "a" * 64}))
        for record in ({"_UID": "0", "CONTAINER_NAME": "samba10-dc"},
                       {"_UID": "0", "CONTAINER_ID_FULL": "b" * 64, "CONTAINER_NAME": "samba-dc"},
                       {"_UID": "1000", "CONTAINER_NAME": "samba-dc"}):
            self.assertFalse(owns_record(source, record))

    def test_samba_auth_record_is_collected_once(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"F2B_STATE_DIR": directory}):
            collector = Collector()
            collector.checkpoint["started"] = 0
            source = {"module": "samba1", "jail": "samba", "uid": "0", "uid_ranges": [(0, 1)],
                      "containers": {"a" * 64: "samba-dc"}}
            collector.sources = [source, {**source, "module": "samba10", "containers": {"b" * 64: "samba-dc"}}]
            message = json.dumps({"type": "Authentication", "Authentication": {
                "status": "NT_STATUS_LOGON_FAILURE", "remoteAddress": "ipv4:198.51.100.5:4500"}})
            record = {"_UID": "0", "CONTAINER_ID_FULL": "a" * 64, "CONTAINER_NAME": "samba-dc",
                      "MESSAGE": message, "__REALTIME_TIMESTAMP": str(int(time.time() * 1_000_000)), "__CURSOR": "x"}
            collector.journal(record)
            self.assertEqual(len((Path(directory) / "logs/samba.log").read_text().splitlines()), 1)

    def test_ssh_auxiliary_records_and_socket_unit(self):
        ip = "198.51.100.9"
        samples = [f"Invalid user scan from {ip} port 2222",
                   f"Connection closed by invalid user scan {ip} port 2222 [preauth]",
                   f"maximum authentication attempts exceeded for invalid user scan from {ip} port 2222 ssh2 [preauth]"]
        for message in samples:
            self.assertEqual(parse("sshd", message), ip)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"F2B_STATE_DIR": directory}):
            collector = Collector()
            collector.checkpoint["started"] = 0
            for i, message in enumerate(samples):
                collector.journal({"_SYSTEMD_UNIT": "sshd@22-198.51.100.9:2222.service", "_PID": "123",
                    "MESSAGE": message, "__CURSOR": str(i),
                    "__REALTIME_TIMESTAMP": str(int(time.time() * 1_000_000))})
            self.assertEqual(len((Path(directory) / "logs/sshd.log").read_text().splitlines()), 1)

    def test_samba_logging_restores_original_only_if_still_ours(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"F2B_STATE_DIR": directory}):
            source = {"module": "samba1", "environment": {}}
            with patch("f2bns8.collector.run_module") as run:
                samba_logging(source)
                self.assertEqual(json.loads((Path(directory) / "samba_loglevel.json").read_text())["samba1"]["present"], False)
                source["environment"]["SAMBA_LOGLEVEL"] = "1 auth_audit:0 auth_json_audit:2"
                with patch("f2bns8.collector.discover", return_value=[source]):
                    restore_samba_logging()
                self.assertTrue(any("unset_env" in str(call) for call in run.call_args_list))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = Registry(self.root / "registry.db")
        self.node = Node(self.root / "node.db")
        self.node.apply(self.registry.snapshot())
        self.node_id = str(uuid.uuid4())

    def tearDown(self):
        self.temp.cleanup()

    def sync(self, protected=None):
        state = self.node.snapshot()
        response = self.registry.sync(self.node_id, "node", state["revision"], state["identity"],
                                      self.node.pending(), state["generation"], protected, 2)
        self.node.apply(response)
        return response

    def test_unchanged_response_and_incremental_bans(self):
        self.sync([])
        clean = self.sync([])
        self.assertTrue(clean["delta"])
        self.assertNotIn("bans", clean)
        self.assertEqual(clean["upserts"], [])
        self.node.ban("198.51.100.12", "sshd", "host", "node", "failure")
        added = self.sync([])
        self.assertEqual([b["ip"] for b in added["upserts"]], ["198.51.100.12"])
        self.assertEqual(len(self.node.bans()), 1)
        self.node.apply(self.registry.unban(["198.51.100.12"]))
        self.assertFalse(self.node.bans())

    def test_protected_vpn_clears_ban_and_rejects_new_attempts(self):
        self.node.ban("10.5.4.8", "samba", "samba1", "node", "failure")
        self.sync([])
        self.assertEqual(len(self.node.bans()), 1)
        self.sync(["10.5.4.0/24", "192.0.2.5/32"])
        self.assertFalse(self.node.bans())
        self.assertIsNone(self.node.ban("10.5.4.8", "samba", "samba1", "node", "failure"))

    def test_pruned_revocation_rejects_offline_event(self):
        stale = Node(self.root / "stale.db")
        stale.apply(self.registry.snapshot())
        event = stale.ban("198.51.100.20", "sshd", "host", "node", "failure")
        self.registry.unban([event["ip"]])
        with database(self.registry.path) as db:
            db.execute("UPDATE bans SET revoked_time=1")
            db.execute("UPDATE changes SET created=1")
            db.execute("UPDATE meta SET value='0' WHERE key='last_prune'")
        self.sync()
        old = stale.snapshot()
        result = self.registry.sync(str(uuid.uuid4()), "stale", old["revision"], old["identity"], [event], old["generation"])
        self.assertEqual(result["results"][0]["result"], "stale")
        stale.apply(result)
        self.assertFalse(stale.pending())

    def test_queue_replays_once_without_mounting_secrets(self):
        with patch.dict(os.environ, {"F2B_STATE_DIR": str(self.root)}):
            (self.root / "engine/queue").mkdir(parents=True)
            enqueue({"ip": "198.51.100.42", "jail": "sshd", "module": "host", "matches": "failure"})
            self.assertEqual(len(list((self.root / "engine/queue").glob("*.json"))), 1)
            drain(self.node, {"node_name": "host", "notifications": {"enabled": True}})
            drain(self.node, {"node_name": "host", "notifications": {"enabled": True}})
            self.assertEqual(len(self.node.pending()), 1)

    def test_read_transaction_does_not_block_writer(self):
        with database(self.node.path, readonly=True) as reader:
            reader.execute("SELECT value FROM kv").fetchall()
            done = threading.Event()
            thread = threading.Thread(target=lambda: (self.node.set("concurrent", True), done.set()), daemon=True)
            thread.start()
            self.assertTrue(done.wait(2), "A WAL reader blocked the worker's write")
            thread.join()

    def test_notifications_stop_after_permanent_or_bounded_failure(self):
        self.node.ban("198.51.100.43", "sshd", "host", "node", "failure")
        with patch("f2bns8.notify.deliver", side_effect=HTTPError("url", 413, "too large", {}, None)):
            process_one(self.node, {"enabled": True})
        with database(self.node.path, readonly=True) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM notifications").fetchone()[0], 0)
        self.node.ban("198.51.100.44", "sshd", "host", "node", "failure")
        with database(self.node.path) as db:
            db.execute("UPDATE notifications SET attempts=?,retry_after=0", (MAX_ATTEMPTS - 1,))
        with patch("f2bns8.notify.deliver", side_effect=TimeoutError("offline")):
            process_one(self.node, {"enabled": True})
        with database(self.node.path, readonly=True) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM notifications").fetchone()[0], 0)


class SurfaceTests(unittest.TestCase):
    def test_cached_interval_whitelist_respects_boundaries_and_families(self):
        whitelist = ["192.0.2.0/25", "192.0.2.128/25", "2001:db8::/126"]
        for ip in ("192.0.2.0", "192.0.2.255", "2001:db8::3", "::ffff:192.0.2.1"):
            self.assertTrue(allowed(ip, whitelist))
        for ip in ("192.0.3.0", "2001:db8::4", "198.51.100.1"):
            self.assertFalse(allowed(ip, whitelist))

    def test_vpn_route_and_local_interface_are_protected(self):
        interfaces = [{"ifname": "eth0", "addr_info": [{"local": "192.0.2.10", "prefixlen": 24}]},
                      {"ifname": "tailscale0", "addr_info": [{"local": "10.5.4.1", "prefixlen": 32}]}]
        routes = [{"dev": "tailscale0", "dst": "10.5.4.0/24"},
                  {"dev": "tailscale0", "dst": "default"}]
        with patch("f2bns8.common.subprocess.run") as run, patch("f2bns8.common.config", return_value={}):
            run.side_effect = [type("Result", (), {"stdout": json.dumps(interfaces)})(),
                               type("Result", (), {"stdout": json.dumps(routes)})()]
            protected = _local_protection(time.monotonic())
        self.assertIn("192.0.2.10/32", protected)
        self.assertIn("10.5.4.0/24", protected)
        self.assertNotIn("0.0.0.0/0", protected)

    @patch.dict(os.environ, {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_failed_first_configuration_is_rolled_back(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"F2B_STATE_DIR": directory}), \
                patch("f2bns8.actions.shutil.which", return_value="/usr/sbin/nft"), \
                patch.object(lifecycle, "route"), patch.object(lifecycle, "start", side_effect=RuntimeError("start failed")), \
                patch.object(lifecycle, "destroy") as destroy:
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                configure({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {"enabled": False}})
            destroy.assert_called_once()
            self.assertFalse((Path(directory) / "config.json").exists())
            self.assertFalse((Path(directory) / "node.sqlite3").exists())

    @patch.dict(os.environ, {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_clone_discards_coordinator_and_its_backup(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"F2B_STATE_DIR": directory}), \
                patch.object(lifecycle, "start"):
            root = Path(directory)
            (root / "backup").mkdir()
            Node(root / "backup/node.sqlite3")
            Registry(root / "backup/coordinator.sqlite3")
            (root / "coordinator.sqlite3").write_bytes(b"stale")
            atomic_json(root / "config.json", {"mode": "coordinator", "public_url": "https://bans.example.org",
                                               "node_id": str(uuid.uuid4())})
            lifecycle.restore(clone=True)
            self.assertFalse((root / "coordinator.sqlite3").exists())
            self.assertFalse((root / "backup/coordinator.sqlite3").exists())
            self.assertEqual(json.loads((root / "config.json").read_text())["mode"], "peer")

    def test_firewall_missing_rule_or_chain_is_not_healthy(self):
        module = "fail2ban1"
        rules = []
        for hook in ("input", "output", "forward"):
            entries = []
            for family, number in (("ip", 4), ("ip6", 6)):
                for direction in (("saddr", "daddr") if hook == "forward" else (("saddr",) if hook == "input" else ("daddr",))):
                    entries.append(f"{family} {direction} @banned{number} counter packets 0 bytes 0 drop")
            rules.append(f"chain {hook} {{ type filter hook {hook} priority -20; policy accept; " + "\n".join(entries) + " }")
        listing = f"table inet {table_name(module)} {{ set banned4 {{ type ipv4_addr; }} set banned6 {{ type ipv6_addr; }} " + " ".join(rules) + " }"
        self.assertTrue(intact(module, listing))
        self.assertFalse(intact(module, listing.replace("ip saddr @banned4 counter packets 0 bytes 0 drop", "")))
        self.assertFalse(intact(module, listing.replace("chain forward", "chain gone")))

    @patch.dict(os.environ, {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_disabled_notifications_keep_stored_token(self):
        old = {"mode": "coordinator", "node_id": str(uuid.uuid4()), "sync_token": "a" * 43,
               "notifications": {"token": "saved-secret"}}
        result = validate({"mode": "coordinator", "public_url": "https://bans.example.org",
                           "notifications": {"enabled": False, "url": ""}}, old)
        self.assertEqual(result["notifications"]["token"], "saved-secret")

    def test_invalid_api_token_is_limited_without_blocking_valid_peers(self):
        with tempfile.TemporaryDirectory() as directory:
            server = make_server(Registry(Path(directory) / "registry.db"), "a" * 43)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = "http://127.0.0.1:" + str(server.server_port)
                statuses = []
                with patch("logging.warning"):
                    for _ in range(11):
                        try:
                            request(base, "wrong", "/v1/state")
                        except HTTPError as error:
                            statuses.append(error.code)
                self.assertEqual(statuses, [401] * 10 + [429])
                self.assertEqual(request(base, "a" * 43, "/v1/state")["revision"], 0)
            finally:
                server.shutdown()
                server.server_close()
