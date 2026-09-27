"""Durable node cache, ban outbox and notification queue."""

import json
import ipaddress
import time
import uuid
from .common import address, allowed, database, local_protection, now, safe_text


class Node:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, ip TEXT UNIQUE NOT NULL, event TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, event TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, retry_after REAL NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS engine_events (id TEXT PRIMARY KEY, created REAL NOT NULL)")

    @staticmethod
    def _snapshot(db):
        row = db.execute("SELECT value FROM kv WHERE key='snapshot'").fetchone()
        return json.loads(row[0]) if row else {"identity": "", "revision": 0, "whitelist_revision": 0,
                                            "whitelist": ["127.0.0.0/8", "::1/128"], "protected": [], "bans": [], "nodes": []}

    def get(self, key, default=None):
        with database(self.path, readonly=True) as db:
            row = db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def set(self, key, value):
        with database(self.path) as db:
            db.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))

    def snapshot(self):
        with database(self.path, readonly=True) as db:
            return self._snapshot(db)

    def ban(self, ip, jail, module, node_name, matches, notify=True, source_id=None):
        ip = address(ip)
        if source_id is not None:
            source_id = str(uuid.UUID(source_id))
        with database(self.path) as db:
            if source_id is not None:
                if db.execute("SELECT 1 FROM engine_events WHERE id=?", (source_id,)).fetchone():
                    return None
                db.execute("INSERT INTO engine_events VALUES (?,?)", (source_id, time.time()))
            snapshot = self._snapshot(db)
            if allowed(ip, snapshot["whitelist"] + snapshot.get("protected", []) + list(local_protection())) or any(b["ip"] == ip for b in snapshot["bans"]):
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

    def prune_engine_events(self):
        with database(self.path) as db:
            db.execute("DELETE FROM engine_events WHERE created<? OR rowid IN "
                       "(SELECT rowid FROM engine_events ORDER BY rowid DESC LIMIT -1 OFFSET 20000)",
                       (time.time() - 30 * 86400,))

    def pending(self):
        with database(self.path, readonly=True) as db:
            return [json.loads(r[0]) for r in db.execute("SELECT event FROM pending ORDER BY rowid LIMIT 100")]

    def apply(self, snapshot):
        if snapshot.get("delta") and not snapshot.get("results"):
            current = self.snapshot()
            if (current["identity"] == snapshot["identity"] and
                    current.get("generation") == snapshot.get("generation") and
                    current["revision"] == snapshot["revision"] == snapshot["base_revision"] and
                    current.get("history_floor", 0) >= snapshot.get("history_floor", 0)):
                return
        with database(self.path) as db:
            old = self._snapshot(db)
            if old["identity"] and old["identity"] != snapshot["identity"]:
                raise ValueError("Coordinator identity changed")
            if snapshot.get("delta"):
                if old.get("generation") != snapshot.get("generation"):
                    raise ValueError("A restored coordinator must send a full snapshot")
                if snapshot["base_revision"] == old["revision"]:
                    bans = {ban["ip"]: ban for ban in old["bans"]}
                    for ip in snapshot["removals"]:
                        bans.pop(ip, None)
                    for ban in snapshot["upserts"]:
                        bans[ban["ip"]] = ban
                    snapshot = {**old, **{k: v for k, v in snapshot.items() if k not in
                        ("delta", "base_revision", "upserts", "removals", "revocations", "policy_revocations")},
                        "bans": list(bans.values()),
                        "revocations": {k: v for k, v in
                            {**old.get("revocations", {}), **snapshot["revocations"]}.items()
                            if v > snapshot.get("history_floor", 0)},
                        "policy_revocations": {k: v for k, v in
                            {**old.get("policy_revocations", {}), **snapshot["policy_revocations"]}.items()
                            if v > snapshot.get("history_floor", 0)}}
                elif snapshot["base_revision"] < old["revision"]:
                    snapshot = {**old, "results": snapshot.get("results", [])}
                else:
                    raise ValueError("Delta begins after the local revision")
            # A new generation means the coordinator was restored from a backup
            # and its revision may be lower than this cache. It is authoritative.
            restored = old.get("generation", "") != snapshot.get("generation", "")
            if snapshot["revision"] < old["revision"] and not restored:
                # A manual task and background sync can complete out of order.
                # Consume acknowledgements but never roll the cache backwards.
                snapshot = {**old, "results": snapshot.get("results", [])}
            for result in snapshot.get("results", []):
                db.execute("DELETE FROM pending WHERE id=?", (result["id"],))
                if result["result"] in ("whitelisted", "revoked", "stale"):
                    db.execute("DELETE FROM notifications WHERE id=?", (result["id"],))
            policies = [(ipaddress.ip_network(net), rev) for net, rev in
                        snapshot.get("policy_revocations", {}).items()]
            protected = snapshot["whitelist"] + snapshot.get("protected", []) + list(local_protection())
            for row in db.execute("SELECT id,ip,event FROM pending").fetchall():
                event = json.loads(row["event"])
                if restored and event["base_revision"] > snapshot["revision"]:
                    event["base_revision"] = snapshot["revision"]
                    db.execute("UPDATE pending SET event=? WHERE id=?", (json.dumps(event), row["id"]))
                base = event["base_revision"]
                revoked = snapshot.get("revocations", {}).get(row["ip"], 0) > base
                revoked = revoked or any(rev > base and ipaddress.ip_address(row["ip"]) in net
                    for net, rev in policies)
                if revoked or base < snapshot.get("history_floor", 0) or allowed(row["ip"], protected):
                    db.execute("DELETE FROM pending WHERE id=?", (row["id"],))
                    db.execute("DELETE FROM notifications WHERE id=?", (row["id"],))
            clean = {k: v for k, v in snapshot.items() if k != "results"}
            db.execute("INSERT OR REPLACE INTO kv VALUES ('snapshot',?)", (json.dumps(clean),))

    def bans(self):
        with database(self.path, readonly=True) as db:
            snapshot = self._snapshot(db)
            bans = {b["ip"]: {**b, "pending": False} for b in snapshot["bans"]}
            for row in db.execute("SELECT event FROM pending"):
                event = json.loads(row[0])
                bans.setdefault(event["ip"], {k: v for k, v in event.items() if k != "matches"})["pending"] = True
            ignored = snapshot["whitelist"] + snapshot.get("protected", []) + list(local_protection())
            return [b for b in bans.values() if not allowed(b["ip"], ignored)]
