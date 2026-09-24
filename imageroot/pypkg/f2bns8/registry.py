"""Single authoritative registry. Transactions serialize bans and manual unbans."""

import json
import uuid
from .common import LOOPBACKS, address, allowed, database, networks, now, safe_text


class Registry:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for key, value in (("revision", "0"), ("whitelist_revision", "0"),
                               ("whitelist", '["127.0.0.0/8", "::1/128"]'),
                               ("identity", str(uuid.uuid4()))):
                db.execute("INSERT OR IGNORE INTO meta VALUES (?, ?)", (key, value))
            db.execute("CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, active INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, result TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, name TEXT NOT NULL, seen TEXT NOT NULL, revision INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS policy_revocations (network TEXT PRIMARY KEY, revision INTEGER NOT NULL)")

    @staticmethod
    def _meta(db):
        return dict(db.execute("SELECT key, value FROM meta"))

    @staticmethod
    def _revision(db):
        value = int(db.execute("SELECT value FROM meta WHERE key='revision'").fetchone()[0]) + 1
        db.execute("UPDATE meta SET value=? WHERE key='revision'", (str(value),))
        return value

    def _snapshot(self, db):
        meta = self._meta(db)
        return {"identity": meta["identity"], "revision": int(meta["revision"]),
                "whitelist_revision": int(meta["whitelist_revision"]),
                "whitelist": json.loads(meta["whitelist"]),
                "revocations": dict(db.execute("SELECT ip,revoked_at FROM bans WHERE revoked_at>0")),
                "policy_revocations": dict(db.execute("SELECT network,revision FROM policy_revocations")),
                "bans": [json.loads(r[0]) for r in db.execute("SELECT detail FROM bans WHERE active=1 ORDER BY ip")],
                "nodes": [dict(r) for r in db.execute("SELECT name,seen,revision FROM nodes ORDER BY name")]}

    def snapshot(self):
        with database(self.path) as db:
            return self._snapshot(db)

    def sync(self, node, name, revision, identity, events):
        uuid.UUID(node)
        if not isinstance(revision, int) or revision < 0 or not isinstance(events, list) or len(events) > 100:
            raise ValueError("Invalid sync request")
        with database(self.path) as db:
            meta = self._meta(db)
            if identity and identity != meta["identity"]:
                raise ValueError("Coordinator identity changed; reconfigure this connection")
            if revision > int(meta["revision"]):
                raise ValueError("Coordinator revision moved backwards; restore its latest database")
            results = []
            for event in events:
                event_id = str(uuid.UUID(event["id"]))
                previous = db.execute("SELECT result FROM events WHERE id=?", (event_id,)).fetchone()
                if previous:
                    results.append(json.loads(previous[0]))
                    continue
                ip = address(event["ip"])
                base = event["base_revision"]
                if not isinstance(base, int) or base < 0 or base > int(meta["revision"]):
                    raise ValueError("Invalid ban revision")
                row = db.execute("SELECT * FROM bans WHERE ip=?", (ip,)).fetchone()
                verdict = "accepted"
                if allowed(ip, json.loads(meta["whitelist"])):
                    verdict = "whitelisted"
                elif (row and row["revoked_at"] > base) or any(
                    rev > base and allowed(ip, [net])
                    for net, rev in db.execute("SELECT network,revision FROM policy_revocations")
                ):
                    verdict = "revoked"
                elif row and row["active"]:
                    verdict = "already-banned"
                else:
                    detail = {"ip": ip, "since": safe_text(event.get("since", now()), 64),
                              "jail": safe_text(event["jail"], 128), "node": safe_text(name, 256),
                              "module": safe_text(event.get("module", ""), 128)}
                    db.execute("INSERT INTO bans VALUES (?,1,0,?) ON CONFLICT(ip) DO UPDATE SET active=1, detail=excluded.detail", (ip, json.dumps(detail)))
                    self._revision(db)
                result = {"id": event_id, "ip": ip, "result": verdict}
                db.execute("INSERT INTO events VALUES (?,?)", (event_id, json.dumps(result)))
                results.append(result)
            db.execute("INSERT INTO nodes VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,seen=excluded.seen,revision=excluded.revision", (node, safe_text(name, 256), now(), revision))
            return {**self._snapshot(db), "results": results}

    def unban(self, ips):
        if not isinstance(ips, list) or not 1 <= len(ips) <= 1000:
            raise ValueError("Select between 1 and 1000 IPs")
        ips = sorted({address(ip) for ip in ips})
        with database(self.path) as db:
            rev = self._revision(db)
            for ip in ips:
                db.execute("INSERT INTO bans VALUES (?,0,?,?) ON CONFLICT(ip) DO UPDATE SET active=0,revoked_at=excluded.revoked_at", (ip, rev, json.dumps({"ip": ip})))
            return self._snapshot(db)

    def set_whitelist(self, values, expected_revision):
        # A host-wide ban on loopback would break the coordinator and other NS8
        # services. These two local-only networks are therefore invariant.
        values = networks(networks(values) + list(LOOPBACKS))
        with database(self.path) as db:
            meta = self._meta(db)
            if expected_revision != int(meta["whitelist_revision"]):
                raise ValueError("Whitelist changed on another node. Refresh before saving.")
            if values == json.loads(meta["whitelist"]):
                return self._snapshot(db)
            rev = self._revision(db)
            db.execute("UPDATE meta SET value=? WHERE key='whitelist'", (json.dumps(values),))
            db.execute("UPDATE meta SET value=? WHERE key='whitelist_revision'", (str(rev),))
            for net in set(values) - set(json.loads(meta["whitelist"])):
                db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?)", (net, rev))
            for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                if allowed(row["ip"], values):
                    db.execute("UPDATE bans SET active=0, revoked_at=? WHERE ip=?", (rev, row["ip"]))
            return self._snapshot(db)
