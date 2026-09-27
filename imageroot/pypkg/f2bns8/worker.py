"""Firewall reconciliation is independent of coordinator and ntfy availability."""
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from . import firewall
from .common import config, networks, now, protected_networks, read_json, state_dir
from .node import Node
from .transport import call


def control(command):
    result = subprocess.run(["podman", "exec", "-i", os.environ["MODULE_ID"] + "-engine",
        "python3", "/opt/control.py"], input=json.dumps(command), text=True,
        capture_output=True, check=True, timeout=15)
    return json.loads(result.stdout)


def synchronize(node, settings):
    snapshot = node.snapshot()
    acks = node.acknowledgments()
    result = call(settings, "/v1/sync", {"node": settings["node_id"], "name": settings["node_name"],
        "identity": snapshot["identity"], "revision": snapshot["revision"],
        "protected": protected_networks(),
        "acks": acks,
        "delta_supported": True,
        "events": [{k: v for k, v in event.items() if k != "matches"} for event in node.pending()]})
    node.apply(result)
    node.confirm_acknowledgments(acks)
    old = node.get("sync_status", {})
    last = old.get("last_success", "")
    try:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds()
    except (ValueError, TypeError):
        elapsed = 60
    if not old.get("ok") or elapsed >= 30:
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
    snapshot = node.snapshot()
    desired = sorted(set(snapshot["whitelist"] + snapshot.get("protected", []) + protected_networks()))
    names = [jail.strip() for jail in jails.split(",") if jail.strip()]
    commands = [["get", jail, key] for jail in names for key in ("banip", "ignoreip")]
    values = control({"batch": commands}) if commands else []
    changes = []
    for index, jail in enumerate(names):
        for ip in values[2 * index]:
            if ip not in wanted:
                changes.append(["set", jail, "unbanip", ip])
        current = networks(values[2 * index + 1])
        for ip in current:
            if ip not in desired:
                changes.append(["set", jail, "delignoreip", ip])
        for ip in desired:
            if ip not in current:
                changes.append(["set", jail, "addignoreip", ip])
    if changes:
        control({"batch": changes})


def consume_engine(node):
    for path in sorted((state_dir() / "engine" / "outbox").glob("*.json")):
        event = read_json(path)
        if event:
            node.ban(event["ip"], event["jail"], event["module"], event["node"],
                     event["matches"], event["notify"])
        path.unlink()


def main():
    settings = config()
    node = Node(state_dir() / "node.sqlite3")
    threading.Thread(target=sync_loop, args=(node, settings), daemon=True).start()
    last_engine, last_firewall, previous, engine_revision = 0, 0, None, None
    while True:
        try:
            consume_engine(node)
        except Exception as error:
            node.set("engine_status", {"ok": False, "error": str(error)[:500]})
        try:
            ips = sorted(b["ip"] for b in node.bans())
            # Reapply periodically to recover from an external firewall reset.
            if ips != previous or time.monotonic() - last_firewall > 15:
                firewall.apply(os.environ["MODULE_ID"], ips)
                last_firewall, previous = time.monotonic(), ips
                node.set("firewall_status", {"ok": True, "updated": now(), "count": len(ips), "error": ""})
        except Exception as error:
            node.set("firewall_status", {"ok": False, "error": str(error)[:500]})
        revision = node.snapshot()["revision"]
        if revision != engine_revision or time.monotonic() - last_engine > 60:
            try:
                reconcile_engine(node)
                node.set("engine_status", {"ok": True, "error": ""})
                engine_revision = revision
            except Exception as error:
                node.set("engine_status", {"ok": False, "error": str(error)[:500]})
            last_engine = time.monotonic()
        time.sleep(0.5)


if __name__ == "__main__":
    main()
