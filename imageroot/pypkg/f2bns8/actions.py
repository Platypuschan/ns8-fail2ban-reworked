"""Small NS8 task API used by the module settings page."""
import json
import os
import re
import secrets
import shutil
import socket
import sys
import uuid
from urllib.error import HTTPError
from .common import atomic_json, config, database, networks, public_host, state_dir, url
from . import lifecycle
from .node import Node
from .registry import Registry
from .transport import call, request


def validate(data, old):
    mode = data.get("mode")
    if mode not in ("coordinator", "peer"):
        raise ValueError("Choose coordinator or connect to a coordinator")
    settings = {"mode": mode, "port": int(os.environ["TCP_PORT"]),
        "node_id": old.get("node_id", str(uuid.uuid4())),
        "node_name": socket.getfqdn() + " / " + os.environ["MODULE_ID"]}
    if old and old["mode"] != mode:
        raise ValueError("Changing an existing coordinator into a peer (or vice versa) requires a new module instance, so two independent databases cannot accidentally be merged")
    token = data.get("sync_token") or old.get("sync_token", "")
    if mode == "coordinator":
        settings["public_url"] = "https://" + public_host(data.get("public_url", ""))
        token = token or secrets.token_urlsafe(32)
    else:
        settings["sync_url"] = url(data.get("sync_url", ""))
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
        raise ValueError("Use the connection token from the coordinator settings")
    settings["sync_token"] = token
    notice = data.get("notifications", {})
    settings["notifications"] = {"enabled": notice.get("enabled", False), "url": "", "topic": "", "token": ""}
    if type(settings["notifications"]["enabled"]) is not bool:
        raise ValueError("Notification enable must be true or false")
    notice_token = notice.get("token") or old.get("notifications", {}).get("token", "")
    if notice.get("clear_token"):
        notice_token = ""
    if not isinstance(notice_token, str) or any(ord(c) < 32 or ord(c) > 126 for c in notice_token):
        raise ValueError("Invalid ntfy token")
    if notice.get("enabled") or notice.get("url"):
        notice_url = url(notice.get("url", ""), https_only=False)
        topic = notice.get("topic", "")
        if not isinstance(topic, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", topic):
            raise ValueError("Enter a valid ntfy topic")
        settings["notifications"].update(url=notice_url, topic=topic, token=notice_token)
    return settings


def configure(data):
    if not shutil.which("nft"):
        raise RuntimeError("The NS8 host needs the nftables command (nft)")
    old = config()
    settings = validate(data, old)
    node = Node(state_dir() / "node.sqlite3")
    if settings["mode"] == "peer":
        snapshot = request(settings["sync_url"], settings["sync_token"], "/v1/state")
        previous = node.snapshot()
        if previous["identity"] and snapshot["identity"] != previous["identity"]:
            raise ValueError("This URL identifies a different coordinator database")
        node.apply(snapshot)
    else:
        node.apply(Registry(state_dir() / "coordinator.sqlite3").snapshot())
    try:
        if settings["mode"] == "coordinator":
            lifecycle.route(settings)
        atomic_json(state_dir() / "config.json", settings)
        lifecycle.start(settings)
    except Exception:
        if old:
            atomic_json(state_dir() / "config.json", old)
            if old["mode"] == "coordinator":
                lifecycle.route(old)
            lifecycle.start(old)
        raise
    return {"configured": True}


def view():
    settings = config()
    node = Node(state_dir() / "node.sqlite3")
    snapshot = node.snapshot()
    notices = settings.get("notifications", {})
    return {"configured": bool(settings), "mode": settings.get("mode", "coordinator"),
        "public_url": settings.get("public_url", ""), "sync_url": settings.get("sync_url", ""),
        "sync_token_configured": bool(settings.get("sync_token")),
        "notifications": {**{k: notices.get(k, "") for k in ("url", "topic")},
            "enabled": notices.get("enabled", False), "token_configured": bool(notices.get("token"))},
        "whitelist": snapshot["whitelist"], "whitelist_revision": snapshot["whitelist_revision"],
        "bans": node.bans(), "sources": node.get("sources", [])}


def diagnostics():
    node = Node(state_dir() / "node.sqlite3")
    with database(node.path) as db:
        pending = db.execute("SELECT count(*) FROM pending").fetchone()[0]
        notifications = db.execute("SELECT count(*) FROM notifications").fetchone()[0]
    return {"revision": node.snapshot()["revision"], "pending_bans": pending,
        "pending_notifications": notifications, "sources": node.get("sources", []),
        "services": {part: lifecycle.systemctl("is-active", os.environ["MODULE_ID"]+"-"+part+".service", check=False).stdout.strip() for part in lifecycle.PARTS},
        **{key: node.get(key, {}) for key in ("sync_status", "firewall_status", "engine_status", "collector_status", "notification_status", "last_detection")}}


def execute(action, data):
    if action == "configure-module":
        return configure(data)
    if action == "get-configuration":
        return view()
    if action == "get-diagnostics":
        return diagnostics()
    if action == "get-connection-token":
        settings = config()
        if settings.get("mode") != "coordinator":
            raise ValueError("The connection token is available on the coordinator")
        return {"sync_token": settings["sync_token"]}
    if action in ("unban-addresses", "set-whitelist"):
        if not config():
            raise ValueError("Configure synchronization first")
        node = Node(state_dir() / "node.sqlite3")
        payload = {"ips": data["ips"]} if action == "unban-addresses" else {
            "whitelist": networks(data["whitelist"]), "revision": data["revision"]}
        snapshot = call(config(), "/v1/unban" if action == "unban-addresses" else "/v1/whitelist", payload)
        node.apply(snapshot)
        return {"revision": snapshot["revision"]}
    if action == "destroy-module":
        lifecycle.destroy()
    elif action in ("restore-module", "clone-module"):
        lifecycle.restore(clone=action == "clone-module")
    elif action == "update-module":
        if config():
            lifecycle.start(config())
    elif action == "dump-state":
        lifecycle.backup()
    elif action != "create-module":
        raise ValueError("Unknown module action")
    return {}


def main():
    try:
        data = json.load(sys.stdin) if not sys.stdin.isatty() and sys.argv[1] not in ("dump-state", "update-module") else {}
        result = execute(sys.argv[1], data)
        print(json.dumps(result))
    except HTTPError as error:
        try:
            detail = json.loads(error.read(4096)).get("error", "Coordinator request failed")
        except (ValueError, AttributeError):
            detail = "Coordinator request failed"
        print(detail, file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
