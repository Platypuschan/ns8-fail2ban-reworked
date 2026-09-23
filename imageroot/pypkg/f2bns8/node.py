"""Durable node cache, ban outbox and notification queue."""

import json
import uuid
from .common import address, allowed, database, now, safe_text


class Node:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, event TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, event TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, retry_after REAL NOT NULL DEFAULT 0)")

    @staticmethod
    def _snapshot(db):
        row = db.execute("SELECT value FROM kv WHERE key='snapshot'").fetchone()
        return json.loads(row[0]) if row else {"identity": "", "revision": 0, "whitelist_revision": 0,
                                            "whitelist": ["127.0.0.0/8", "::1/128"], "bans": [], "nodes": []}

    def get(self, key, default=None):
        with database(self.path) as db:
            row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, key, value):
        with database(self.path) as db:
            db.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))

    def snapshot(self):
        with database(self.path) as db:
            return self._snapshot(db)

    def ban(self, ip, jail, module, node_name, matches, notify=True):
        ip = address(ip)
        with database(self.path) as db:
            snapshot = self._snapshot(db)
            if allowed(ip, snapshot["whitelist"]) or any(b["ip"] == ip for b in snapshot["bans"]):
                return None
            if db.execute("SELECT 1 FROM pending WHERE ip=?", (ip,)).fetchone():
                return None
            event = {"id": str(uuid.uuid4()), "ip": ip, "base_revision": snapshot["revision"],
                     "jail": safe_text(jail, 128), "module": safe_text(module, 128),
                     "node": safe_text(node_name, 256), "since": now(),
                     "matches": safe_text(matches, 32768)}
            db.execute("INSERT INTO pending VALUES (?,?,?)", (event["id"], ip, json.dumps(event)))
            if notify:
                db.execute("INSERT INTO notifications(id,event) VALUES (?,?)", (event["id"], json.dumps(event)))
            return event

    def pending(self):
        with database(self.path) as db:
            return [json.loads(r[0]) for r in db.execute("SELECT event FROM pending ORDER BY rowid LIMIT 100")]

    def apply(self, snapshot):
        with database(self.path) as db:
            old = self._snapshot(db)
            if old["identity"] and old["identity"] != snapshot["identity"]:
                raise ValueError("Coordinator identity changed")
            if snapshot["revision"] < old["revision"]:
                # A manual task and background sync can complete out of order.
                # Consume acknowledgements but never roll the cache backwards.
                snapshot = {**old, "results": snapshot.get("results", [])}
            for result in snapshot.get("results", []):
                db.execute("DELETE FROM pending WHERE id=?", (result["id"],))
                if result["result"] in ("whitelisted", "revoked"):
                    db.execute("DELETE FROM notifications WHERE id=?", (result["id"],))
            for row in db.execute("SELECT id,ip,event FROM pending").fetchall():
                base = json.loads(row["event"])["base_revision"]
                revoked = snapshot.get("revocations", {}).get(row["ip"], 0) > base
                revoked = revoked or any(rev > base and allowed(row["ip"], [net])
                    for net, rev in snapshot.get("policy_revocations", {}).items())
                if revoked or allowed(row["ip"], snapshot["whitelist"]):
                    db.execute("DELETE FROM pending WHERE id=?", (row["id"],))
                    db.execute("DELETE FROM notifications WHERE id=?", (row["id"],))
            clean = {k: v for k, v in snapshot.items() if k != "results"}
            db.execute("INSERT OR REPLACE INTO kv VALUES ('snapshot',?)", (json.dumps(clean),))

    def bans(self):
        with database(self.path) as db:
            snapshot = self._snapshot(db)
            bans = {b["ip"]: {**b, "pending": False} for b in snapshot["bans"]}
            for row in db.execute("SELECT event FROM pending"):
                event = json.loads(row[0])
                bans.setdefault(event["ip"], {k: v for k, v in event.items() if k != "matches"})["pending"] = True
            return [b for b in bans.values() if not allowed(b["ip"], snapshot["whitelist"])]
