"""Firewall reconciliation is independent of coordinator and ntfy availability."""
import json
import os
import subprocess
import threading
import time
from . import firewall
from .common import config, local_protection, now, state_dir
from .node import Node
from .queue import drain
from .transport import call


def control(command):
    result = subprocess.run(["podman", "exec", "-i", os.environ["MODULE_ID"] + "-engine",
        "python3", "/opt/control.py"], input=json.dumps(command), text=True,
        capture_output=True, check=True, timeout=60)
    return json.loads(result.stdout)


def synchronize(node, settings):
    snapshot = node.snapshot()
    result = call(settings, "/v1/sync", {"node": settings["node_id"], "name": settings["node_name"],
        "identity": snapshot["identity"], "generation": snapshot.get("generation", ""),
        "revision": snapshot["revision"], "protocol": 2,
        "protected": list(local_protection()),
        "events": [{k: v for k, v in event.items() if k != "matches"} for event in node.pending()]})
    node.apply(result)


def sync_loop(node, settings):
    last_status = 0
    healthy = False
    while True:
        try:
            synchronize(node, settings)
            if not healthy or time.monotonic() - last_status > 60:
                node.set("sync_status", {"ok": True, "last_success": now(), "error": ""})
                last_status = time.monotonic()
            healthy = True
        except Exception as error:
            if healthy or time.monotonic() - last_status > 60:
                old = node.get("sync_status", {})
                node.set("sync_status", {**old, "ok": False, "error": str(error)[:500]})
                last_status = time.monotonic()
            healthy = False
        time.sleep(3)


def reconcile_engine(ips, whitelist):
    return control({"reconcile": {"bans": ips, "whitelist": whitelist}})


def main():
    settings = config()
    node = Node(state_dir() / "node.sqlite3")
    threading.Thread(target=sync_loop, args=(node, settings), daemon=True).start()
    last_engine, last_engine_status, last_firewall, previous, engine_state, engine_ok = 0, 0, 0, None, None, False
    while True:
        ips = previous or []
        try:
            drain(node, settings)
            ips = sorted(b["ip"] for b in node.bans())
            # Reapply periodically to recover from an external firewall reset.
            if ips != previous or time.monotonic() - last_firewall > 15:
                firewall.apply(os.environ["MODULE_ID"], ips)
                last_firewall, previous = time.monotonic(), ips
                node.set("firewall_status", {"ok": True, "updated": now(), "count": len(ips), "error": ""})
        except Exception as error:
            node.set("firewall_status", {"ok": False, "error": str(error)[:500]})
        snapshot = node.snapshot()
        ignore = sorted(set(snapshot["whitelist"] + snapshot.get("protected", []) + list(local_protection())))
        wanted_state = (tuple(ips) if previous is not None else (), tuple(ignore))
        if wanted_state != engine_state or time.monotonic() - last_engine > 60:
            try:
                reconcile_engine(ips, ignore)
                if not engine_ok or time.monotonic() - last_engine_status > 60:
                    node.set("engine_status", {"ok": True, "error": ""})
                    last_engine_status = time.monotonic()
                engine_state, engine_ok = wanted_state, True
            except Exception as error:
                if engine_ok or time.monotonic() - last_engine_status > 60:
                    node.set("engine_status", {"ok": False, "error": str(error)[:500]})
                    last_engine_status = time.monotonic()
                engine_ok = False
            last_engine = time.monotonic()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
