"""Run inside an ephemeral NS8 VM, via the installed module's runagent."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from f2bns8.common import config, state_dir
from f2bns8.firewall import table_name
from f2bns8.lifecycle import PARTS
from f2bns8.node import Node
from f2bns8.transport import call

module = os.environ["MODULE_ID"]
node = Node(state_dir() / "node.sqlite3")
settings = config()


def task(action, payload=None):
    output = subprocess.check_output(["api-cli", "run", "module/" + module + "/" + action,
        "--data", json.dumps(payload or {})], text=True)
    return json.loads(output)


def wait_for(check, description, seconds=40):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            print("PASS:", description, flush=True)
            return
        time.sleep(1)
    raise AssertionError("Timed out: " + description)


def login():
    return subprocess.run(["ip", "netns", "exec", "f2b-attacker", "curl", "-ksS",
        "--max-time", "3", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", "Content-Type: application/json", "-d", '{"username":"admin","password":"deliberately-wrong"}',
        "https://192.0.2.1/cluster-admin/api/login"], capture_output=True, text=True)


for part in PARTS:
    subprocess.run(["systemctl", "is-active", "--quiet", module + "-" + part + ".service"], check=True)
wait_for(lambda: node.get("sync_status", {}).get("ok") and node.get("engine_status", {}).get("ok"), "coordinator automatically synchronizes its own node")
wait_for(lambda: any(s["jail"] == "ns8" and s["ready"] for s in node.get("sources", [])), "NS8 Traefik discovery")
for number in range(4):
    result = login()
    assert result.stdout == "401", result
time.sleep(3)
assert not node.bans(), node.bans()
assert not Path("/tmp/ns8-notifications.jsonl").exists()
assert login().stdout == "401"
wait_for(lambda: any(b["ip"] == "192.0.2.2" for b in node.bans()), "five real failed NS8 logins trigger a ban")
wait_for(lambda: Path("/tmp/ns8-notifications.jsonl").exists(), "ntfy receives the ban notification")
payload = json.loads(Path("/tmp/ns8-notifications.jsonl").read_text().splitlines()[0])
for expected in ("192.0.2.2", "Time:", "Jail: ns8", module, "POST /cluster-admin/api/login"):
    assert expected in payload, (expected, payload)
wait_for(lambda: login().returncode != 0, "all incoming traffic from banned IP is blocked")

# The public route must reach the loopback-only sync service through Traefik.
route_result = subprocess.run(["curl", "-ksS", "--resolve", "bans.ns8.test:443:127.0.0.1",
    "-H", "Authorization: Bearer " + settings["sync_token"], "https://bans.ns8.test/v1/state"], capture_output=True, text=True, check=True)
assert json.loads(route_result.stdout)["identity"] == node.snapshot()["identity"]
print("PASS: NS8 reverse proxy reaches the embedded coordinator", flush=True)

# Emulate the authenticated synchronization message from a second module.
snapshot = node.snapshot()
call(settings, "/v1/sync", {"node": str(uuid.uuid4()), "name": "other NS8 node", "revision": snapshot["revision"],
    "identity": snapshot["identity"], "events": [{"id": str(uuid.uuid4()), "ip": "203.0.113.7", "base_revision": snapshot["revision"], "jail": "sshd", "module": "host"}]})
wait_for(lambda: any(b["ip"] == "203.0.113.7" for b in node.bans()), "imported ban reaches local enforcement")
time.sleep(3)
assert len(Path("/tmp/ns8-notifications.jsonl").read_text().splitlines()) == 1

task("unban-addresses", {"ips": ["192.0.2.2", "203.0.113.7"]})
wait_for(lambda: not node.bans(), "shared manual unban clears the list")
task("set-whitelist", {"whitelist": ["127.0.0.0/8", "::1", "192.0.2.0/24"], "revision": node.snapshot()["whitelist_revision"]})
wait_for(lambda: login().stdout == "401", "unblocked/whitelisted address can communicate again")
for _ in range(6):
    assert login().stdout == "401"
time.sleep(3)
assert not node.bans()
assert len(Path("/tmp/ns8-notifications.jsonl").read_text().splitlines()) == 1
print("PASS: shared whitelist suppresses bans and notifications", flush=True)

subprocess.run(["module-dump-state"], check=True)
assert (state_dir() / "backup/coordinator.sqlite3").exists()
assert (state_dir() / "backup/node.sqlite3").exists()
subprocess.run(["systemctl", "restart", module + "-engine.service", module + "-worker.service"], check=True)
wait_for(lambda: node.get("engine_status", {}).get("ok"), "services restart successfully")
print("PASS: SQLite backup snapshots created", flush=True)
print("NS8_SMOKE_OK", flush=True)
