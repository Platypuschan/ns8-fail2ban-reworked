"""Only local threshold-triggered bans enter this durable delivery queue."""
import json
import time
from urllib.parse import quote
from urllib.request import Request, build_opener
from .common import config, database, now, state_dir
from .node import Node
from .transport import NoRedirects


def message(event):
    return ("Permanent IP ban\n\nAddress: " + event["ip"] + "\nTime: " + event["since"]
        + "\nJail: " + event["jail"] + "\nNode: " + event["node"]
        + "\nModule: " + event["module"] + "\n\nMatching login failures:\n" + event["matches"])


def deliver(settings, event):
    body = message(event).encode("utf-8")
    # ntfy's standard message limit is 4096 bytes. Preserve complete logs as an attachment.
    headers = {"Title": "Fail2ban: " + event["ip"], "Tags": "shield,lock"}
    if len(body) > 4000:
        headers["Filename"] = "fail2ban-" + event["id"] + ".txt"
        headers["Message"] = "Permanent ban: " + event["ip"] + ". Full matching log lines attached."
    if settings.get("token"):
        headers["Authorization"] = "Bearer " + settings["token"]
    headers["Content-Type"] = "text/plain; charset=utf-8"
    req = Request(settings["url"] + "/" + quote(settings["topic"], safe=""), data=body, headers=headers)
    with build_opener(NoRedirects).open(req, timeout=10) as response:
        response.read(4096)


def main():
    node = Node(state_dir() / "node.sqlite3")
    while True:
        settings = config().get("notifications", {})
        with database(node.path) as db:
            if not settings.get("enabled"):
                db.execute("DELETE FROM notifications")
            row = db.execute("SELECT * FROM notifications WHERE retry_after<=? ORDER BY rowid LIMIT 1", (time.time(),)).fetchone()
        if row:
            try:
                deliver(settings, json.loads(row["event"]))
                with database(node.path) as db:
                    db.execute("DELETE FROM notifications WHERE id=?", (row["id"],))
                node.set("notification_status", {"ok": True, "last_success": now(), "error": ""})
            except Exception as error:
                delay = min(3600, 5 * 2 ** min(row["attempts"], 10))
                with database(node.path) as db:
                    db.execute("UPDATE notifications SET attempts=attempts+1,retry_after=? WHERE id=?", (time.time()+delay, row["id"]))
                node.set("notification_status", {"ok": False, "error": str(error)[:500]})
        time.sleep(1)


if __name__ == "__main__":
    main()
