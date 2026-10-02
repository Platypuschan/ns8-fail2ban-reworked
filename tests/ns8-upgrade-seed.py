"""Run with the previous release's code: create state that an update must keep."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from f2bns8.common import config, now, state_dir
from f2bns8.node import Node
from f2bns8.transport import call

module = os.environ["MODULE_ID"]
node = Node(state_dir() / "node.sqlite3")
settings = config()


def wait_for(check, description, seconds=60):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            print("PASS:", description, flush=True)
            return
        time.sleep(1)
    raise AssertionError("Timed out: " + description)


wait_for(lambda: node.get("sync_status", {}).get("ok") and node.get("engine_status", {}).get("ok"),
         "previous release synchronizes its own node")
# Since 0.2.0 a new peer registers first and acknowledges the rebase before
# the coordinator accepts its events.
snapshot = node.snapshot()
peer = {"node": str(uuid.uuid4()), "name": "other NS8 node", "delta_supported": True}
registration = call(settings, "/v1/sync", {**peer, "revision": snapshot["revision"],
    "identity": snapshot["identity"], "events": []})
imported = call(settings, "/v1/sync", {**peer, "revision": registration["revision"],
    "identity": registration["identity"], "rebase_ack": registration["rebase_nonce"],
    "events": [{"id": str(uuid.uuid4()), "ip": "203.0.113.9", "base_revision": registration["revision"],
                "jail": "sshd", "module": "host", "since": now()}]})
assert imported["results"][0]["result"] == "accepted", imported["results"]
wait_for(lambda: any(b["ip"] == "203.0.113.9" for b in node.bans()), "previous release stores a ban")
subprocess.run(["api-cli", "run", "module/" + module + "/set-whitelist", "--data", json.dumps({
    "whitelist": ["127.0.0.0/8", "::1", "198.51.100.0/24"],
    "revision": node.snapshot()["whitelist_revision"]})], check=True, stdout=subprocess.DEVNULL)
wait_for(lambda: "198.51.100.0/24" in node.snapshot()["whitelist"], "previous release stores a whitelist entry")
Path("/tmp/f2b-upgrade.json").write_text(json.dumps({
    "sync_token": settings["sync_token"], "identity": node.snapshot()["identity"]}))
