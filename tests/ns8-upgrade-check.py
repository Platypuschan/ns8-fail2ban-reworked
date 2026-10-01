"""Run with the tested code after update-module: the previous state must survive."""
import json
import os
from pathlib import Path
import subprocess
import time

from f2bns8.common import config, state_dir
from f2bns8.lifecycle import PARTS
from f2bns8.node import Node

module = os.environ["MODULE_ID"]
node = Node(state_dir() / "node.sqlite3")
settings = config()
before = json.loads(Path("/tmp/f2b-upgrade.json").read_text())


def wait_for(check, description, seconds=90):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            print("PASS:", description, flush=True)
            return
        time.sleep(1)
    print("STATUS:", node.get("sync_status"), node.get("engine_status"), node.get("firewall_status"), flush=True)
    raise AssertionError("Timed out: " + description)


def active(part):
    return subprocess.run(["systemctl", "is-active", "--quiet", module + "-" + part + ".service"]).returncode == 0


wait_for(lambda: all(active(part) for part in PARTS), "all services run after the update")
wait_for(lambda: node.get("sync_status", {}).get("ok") and node.get("engine_status", {}).get("ok"),
         "updated node synchronizes and controls the engine")
assert settings["sync_token"] == before["sync_token"], "sync token changed"
assert node.snapshot()["identity"] == before["identity"], "coordinator identity changed"
print("PASS: update keeps the coordinator identity and sync token", flush=True)
assert any(b["ip"] == "203.0.113.9" for b in node.bans()), node.bans()
assert "198.51.100.0/24" in node.snapshot()["whitelist"], node.snapshot()["whitelist"]
print("PASS: update keeps bans and whitelist", flush=True)
engine = json.loads(subprocess.check_output(["podman", "inspect", module + "-engine"], text=True))[0]
assert engine["Config"]["User"] == "65532:65532", engine["Config"]["User"]
assert engine["ImageName"] == os.environ["FAIL2BAN_ENGINE_IMAGE"], (engine["ImageName"], os.environ["FAIL2BAN_ENGINE_IMAGE"])
print("PASS: engine runs the updated image without root", flush=True)
wait_for(lambda: "203.0.113.9" in subprocess.check_output(["nft", "list", "ruleset"], text=True),
         "kept ban is enforced by the firewall")
print("NS8_UPGRADE_OK", flush=True)
