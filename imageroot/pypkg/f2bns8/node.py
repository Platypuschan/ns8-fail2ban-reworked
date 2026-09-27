"""Durable node cache, ban outbox and notification queue."""

import json
import uuid
from .common import address, allowed, database, now, protected_networks, safe_text


class Node:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, event TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, event TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, retry_after REAL NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS acknowledgments (id TEXT PRIMARY KEY)")

    @staticmethod
    def _snapshot(db):
        row = db.execute("SELECT value FROM kv WHERE key='snapshot'").fetchone()
        return json.loads(row[0]) if row else {"identity": "", "revision": 0, "whitelist_revision": 0,
                                            "whitelist": ["127.0.0.0/8", "::1/128"], "bans": [], "nodes": []}

    def get(self, key, default=None):
        with database(self.path, write=False) as db:
            row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, key, value):
        with database(self.path) as db:
            db.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))

    def snapshot(self):
        with database(self.path, write=False) as db:
            return self._snapshot(db)

    def ban(self, ip, jail, module, node_name, matches, notify=True):
        ip = address(ip)
        with database(self.path) as db:
            snapshot = self._snapshot(db)
            if allowed(ip, snapshot["whitelist"] + snapshot.get("protected", []) + protected_networks()) or any(b["ip"] == ip for b in snapshot["bans"]):
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
        with database(self.path, write=False) as db:
            return [json.loads(r[0]) for r in db.execute("SELECT event FROM pending ORDER BY rowid LIMIT 100")]

    def acknowledgments(self):
        with database(self.path, write=False) as db:
            return [row[0] for row in db.execute("SELECT id FROM acknowledgments LIMIT 100")]

    def confirm_acknowledgments(self, ids):
        if ids:
            with database(self.path) as db:
                db.executemany("DELETE FROM acknowledgments WHERE id=?", ((item,) for item in ids))

    def apply(self, snapshot):
        if snapshot.get("unchanged"):
            old = self.snapshot()
            if old["identity"] and old["identity"] != snapshot["identity"]:
                raise ValueError("Coordinator identity changed")
            if snapshot["revision"] > old["revision"]:
                raise ValueError("Invalid unchanged response")
            return
        with database(self.path) as db:
            old = self._snapshot(db)
            if old["identity"] and old["identity"] != snapshot["identity"]:
                raise ValueError("Coordinator identity changed")
            if snapshot.get("reset_pending") and snapshot["revision"] >= old["revision"]:
                db.execute("DELETE FROM notifications WHERE id IN (SELECT id FROM pending)")
                db.execute("DELETE FROM pending")
                db.execute("DELETE FROM acknowledgments")
            if snapshot["revision"] >= old["revision"] and "rebase_nonce" in snapshot:
                db.execute("INSERT OR REPLACE INTO kv VALUES ('rebase_nonce',?)",
                           (json.dumps(snapshot["rebase_nonce"]),))
            if snapshot["revision"] < old["revision"]:
                # A manual task and background sync can complete out of order.
                # Consume acknowledgements but never roll the cache backwards.
                snapshot = {**old, "results": snapshot.get("results", [])}
            elif snapshot.get("delta"):
                bans = {ban["ip"]: ban for ban in old["bans"]}
                for change in snapshot["changes"]:
                    if change["detail"] is None:
                        bans.pop(change["ip"], None)
                    else:
                        bans[change["ip"]] = change["detail"]
                snapshot = {**old, **snapshot, "bans": list(bans.values()),
                    "revocations": {**old.get("revocations", {}), **snapshot["revocations"]},
                    "policy_revocations": {**old.get("policy_revocations", {}), **snapshot["policy_revocations"]}}
            for result in snapshot.get("results", []):
                db.execute("DELETE FROM pending WHERE id=?", (result["id"],))
                db.execute("INSERT OR IGNORE INTO acknowledgments VALUES (?)", (result["id"],))
                if result["result"] in ("whitelisted", "revoked", "expired"):
                    db.execute("DELETE FROM notifications WHERE id=?", (result["id"],))
            for row in db.execute("SELECT id,ip,event FROM pending").fetchall():
                base = json.loads(row["event"])["base_revision"]
                revoked = base < snapshot.get("retention_floor", 0)
                revoked = revoked or snapshot.get("revocations", {}).get(row["ip"], 0) > base
                revoked = revoked or any(rev > base and allowed(row["ip"], [net])
                    for net, rev in snapshot.get("policy_revocations", {}).items())
                if revoked or allowed(row["ip"], snapshot["whitelist"] + snapshot.get("protected", [])):
                    db.execute("DELETE FROM pending WHERE id=?", (row["id"],))
                    db.execute("DELETE FROM notifications WHERE id=?", (row["id"],))
            clean = {k: v for k, v in snapshot.items()
                     if k not in ("results", "delta", "changes", "reset_pending", "rebase_nonce")}
            outstanding = [json.loads(row[0])["base_revision"] for row in db.execute("SELECT event FROM pending")]
            floor = min(outstanding) if outstanding else clean["revision"]
            clean["revocations"] = {ip: rev for ip, rev in clean.get("revocations", {}).items() if rev > floor}
            clean["policy_revocations"] = {net: rev for net, rev in clean.get("policy_revocations", {}).items() if rev > floor}
            db.execute("INSERT OR REPLACE INTO kv VALUES ('snapshot',?)", (json.dumps(clean),))

    def bans(self):
        with database(self.path, write=False) as db:
            snapshot = self._snapshot(db)
            bans = {b["ip"]: {**b, "pending": False} for b in snapshot["bans"]}
            for row in db.execute("SELECT event FROM pending"):
                event = json.loads(row[0])
                bans.setdefault(event["ip"], {k: v for k, v in event.items() if k != "matches"})["pending"] = True
            protection = snapshot["whitelist"] + snapshot.get("protected", []) + protected_networks()
            return [b for b in bans.values() if not allowed(b["ip"], protection)]
