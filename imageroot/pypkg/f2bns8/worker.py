"""Firewall reconciliation is independent of coordinator and ntfy availability."""
import json
import os
import subprocess
import threading
import time
from . import firewall
from .common import config, now, state_dir
from .node import Node
from .transport import call


def control(command):
    result = subprocess.run(["podman", "exec", "-i", os.environ["MODULE_ID"] + "-engine",
        "python3", "/opt/control.py"], input=json.dumps(command), text=True,
        capture_output=True, check=True, timeout=15)
    return json.loads(result.stdout)


def synchronize(node, settings):
    snapshot = node.snapshot()
    result = call(settings, "/v1/sync", {"node": settings["node_id"], "name": settings["node_name"],
        "identity": snapshot["identity"], "revision": snapshot["revision"],
        "events": [{k: v for k, v in event.items() if k != "matches"} for event in node.pending()]})
    node.apply(result)
    node.set("sync_status", {"ok": True, "last_success": now(), "error": ""})


def sync_loop(node, settings):
    while True:
        try:
            synchronize(node, settings)
        except Exception as error:
            old = node.get("sync_status", {})
            node.set("sync_status", {**old, "ok": False, "error": str(error)[:500]})
        time.sleep(3)


def reconcile_engine(node):
    wanted = {ban["ip"] for ban in node.bans()}
    status = control(["status"])
    jails = next((item[1] for item in status if "Jail list" in item[0]), "")
    for jail in jails.split(","):
        jail = jail.strip()
        if not jail:
            continue
        for ip in control(["get", jail, "banip"]):
            if ip not in wanted:
                control(["set", jail, "unbanip", ip])
        current = control(["get", jail, "ignoreip"])
        desired = node.snapshot()["whitelist"]
        for ip in current:
            if ip not in desired:
                control(["set", jail, "delignoreip", ip])
        for ip in desired:
            if ip not in current:
                control(["set", jail, "addignoreip", ip])


def main():
    settings = config()
    node = Node(state_dir() / "node.sqlite3")
    threading.Thread(target=sync_loop, args=(node, settings), daemon=True).start()
    last_engine, last_firewall, previous = 0, 0, None
    while True:
        try:
            ips = sorted(b["ip"] for b in node.bans())
            # Reapply periodically to recover from an external firewall reset.
            if ips != previous or time.monotonic() - last_firewall > 15:
                firewall.apply(os.environ["MODULE_ID"], ips)
                last_firewall, previous = time.monotonic(), ips
                node.set("firewall_status", {"ok": True, "updated": now(), "count": len(ips), "error": ""})
        except Exception as error:
            node.set("firewall_status", {"ok": False, "error": str(error)[:500]})
        if time.monotonic() - last_engine > 5:
            try:
                reconcile_engine(node)
                node.set("engine_status", {"ok": True, "error": ""})
            except Exception as error:
                node.set("engine_status", {"ok": False, "error": str(error)[:500]})
            last_engine = time.monotonic()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
