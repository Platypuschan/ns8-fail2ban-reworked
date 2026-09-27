"""Single authoritative registry. Transactions serialize bans and manual unbans."""

import json
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
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
            db.execute("CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, active INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL, changed_at INTEGER NOT NULL DEFAULT 0)")
            if "changed_at" not in {row[1] for row in db.execute("PRAGMA table_info(bans)")}:
                db.execute("ALTER TABLE bans ADD COLUMN changed_at INTEGER NOT NULL DEFAULT 0")
                db.execute("UPDATE bans SET changed_at=(SELECT CAST(value AS INTEGER) FROM meta WHERE key='revision')")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, result TEXT NOT NULL, node TEXT NOT NULL DEFAULT '')")
            if "node" not in {row[1] for row in db.execute("PRAGMA table_info(events)")}:
                db.execute("ALTER TABLE events ADD COLUMN node TEXT NOT NULL DEFAULT ''")
                # Old rows cannot be acknowledged by node ID. A replay still
                # resolves against the active ban and permanent revocation
                # markers, so they need not remain in the live event table.
                db.execute("DELETE FROM events WHERE node=''")
            db.execute("CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, name TEXT NOT NULL, seen TEXT NOT NULL, revision INTEGER NOT NULL, protected TEXT NOT NULL DEFAULT '[]')")
            if "protected" not in {row[1] for row in db.execute("PRAGMA table_info(nodes)")}:
                db.execute("ALTER TABLE nodes ADD COLUMN protected TEXT NOT NULL DEFAULT '[]'")
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
        protected = self._snapshot_protected(db)
        return {"identity": meta["identity"], "revision": int(meta["revision"]),
                "whitelist_revision": int(meta["whitelist_revision"]),
                "whitelist": json.loads(meta["whitelist"]),
                "protected": protected,
                "revocations": dict(db.execute("SELECT ip,revoked_at FROM bans WHERE revoked_at>0")),
                "policy_revocations": dict(db.execute("SELECT network,revision FROM policy_revocations")),
                "bans": [json.loads(r[0]) for r in db.execute("SELECT detail FROM bans WHERE active=1 ORDER BY ip")],
                "nodes": [dict(r) for r in db.execute("SELECT name,seen,revision FROM nodes ORDER BY name")]}

    def snapshot(self):
        with database(self.path, write=False) as db:
            return self._snapshot(db)

    def _delta(self, db, since):
        meta = self._meta(db)
        result = {"identity": meta["identity"], "revision": int(meta["revision"]),
                  "delta": True, "protected": self._snapshot_protected(db),
                  "changes": [{"ip": row["ip"], "detail": json.loads(row["detail"]) if row["active"] else None}
                      for row in db.execute("SELECT ip,active,detail FROM bans WHERE changed_at>?", (since,))],
                  "revocations": dict(db.execute("SELECT ip,revoked_at FROM bans WHERE revoked_at>?", (since,))),
                  "policy_revocations": dict(db.execute("SELECT network,revision FROM policy_revocations WHERE revision>?", (since,)))}
        if int(meta["whitelist_revision"]) > since:
            result.update(whitelist=json.loads(meta["whitelist"]),
                          whitelist_revision=int(meta["whitelist_revision"]))
        return result

    @staticmethod
    def _snapshot_protected(db):
        return sorted({net for row in db.execute("SELECT protected FROM nodes")
            for net in json.loads(row[0])})

    def sync(self, node, name, revision, identity, events, protected=None, acks=None, delta_supported=False):
        uuid.UUID(node)
        if not isinstance(revision, int) or revision < 0 or not isinstance(events, list) or len(events) > 100:
            raise ValueError("Invalid sync request")
        if protected is not None and (not isinstance(protected, list) or len(protected) > 128):
            raise ValueError("Too many protected networks")
        if not isinstance(acks or [], list) or len(acks or []) > 100:
            raise ValueError("Too many acknowledgments")
        acks = [str(uuid.UUID(item)) for item in (acks or [])]
        protected = networks(protected or [])
        if any(ipaddress.ip_network(value).prefixlen == 0 for value in protected):
            raise ValueError("Protected networks cannot include a default route")
        with database(self.path) as db:
            meta = self._meta(db)
            if identity and identity != meta["identity"]:
                raise ValueError("Coordinator identity changed; reconfigure this connection")
            if revision > int(meta["revision"]):
                raise ValueError("Coordinator revision moved backwards; restore its latest database")
            cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(timespec="seconds")
            stale = db.execute("SELECT id,protected FROM nodes WHERE seen<? AND id!=?", (cutoff, node)).fetchall()
            if stale:
                db.executemany("DELETE FROM events WHERE node=?", ((row["id"],) for row in stale))
                db.executemany("DELETE FROM nodes WHERE id=?", ((row["id"],) for row in stale))
                if any(json.loads(row["protected"]) for row in stale):
                    self._revision(db)
            db.executemany("DELETE FROM events WHERE id=? AND node=?", ((item, node) for item in acks))
            prior = db.execute("SELECT protected FROM nodes WHERE id=?", (node,)).fetchone()
            old_protected = json.loads(prior[0]) if prior else []
            if protected != old_protected:
                protection_revision = self._revision(db)
                for net in set(protected) - set(old_protected):
                    db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?)", (net, protection_revision))
            all_protected = sorted({net for row in db.execute("SELECT protected FROM nodes WHERE id!=?", (node,))
                for net in json.loads(row[0])} | set(protected))
            whitelist = json.loads(meta["whitelist"]) + all_protected
            if protected != old_protected:
                for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                    if allowed(row["ip"], whitelist):
                        db.execute("UPDATE bans SET active=0,revoked_at=?,changed_at=? WHERE ip=?", (protection_revision, protection_revision, row["ip"]))
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
                if allowed(ip, whitelist):
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
                    ban_revision = self._revision(db)
                    db.execute("INSERT INTO bans(ip,active,revoked_at,detail,changed_at) VALUES (?,1,0,?,?) ON CONFLICT(ip) DO UPDATE SET active=1, detail=excluded.detail,changed_at=excluded.changed_at", (ip, json.dumps(detail), ban_revision))
                result = {"id": event_id, "ip": ip, "result": verdict}
                db.execute("INSERT INTO events VALUES (?,?,?)", (event_id, json.dumps(result), node))
                results.append(result)
            db.execute("INSERT INTO nodes(id,name,seen,revision,protected) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,seen=excluded.seen,revision=excluded.revision,protected=excluded.protected", (node, safe_text(name, 256), now(), revision, json.dumps(protected)))
            current_revision = int(db.execute("SELECT value FROM meta WHERE key='revision'").fetchone()[0])
            if delta_supported and revision == current_revision and protected == old_protected and not results:
                return {"identity": meta["identity"], "revision": revision,
                        "unchanged": True, "results": []}
            if identity and delta_supported:
                return {**self._delta(db, revision), "results": results}
            return {**self._snapshot(db), "results": results}

    def unban(self, ips):
        if not isinstance(ips, list) or not 1 <= len(ips) <= 1000:
            raise ValueError("Select between 1 and 1000 IPs")
        ips = sorted({address(ip) for ip in ips})
        with database(self.path) as db:
            rev = self._revision(db)
            for ip in ips:
                db.execute("INSERT INTO bans(ip,active,revoked_at,detail,changed_at) VALUES (?,0,?,?,?) ON CONFLICT(ip) DO UPDATE SET active=0,revoked_at=excluded.revoked_at,changed_at=excluded.changed_at", (ip, rev, json.dumps({"ip": ip}), rev))
            return self._snapshot(db)

    def set_whitelist(self, values, expected_revision):
        # A host-wide ban on loopback would break the coordinator and other NS8
        # services. These two local-only networks are therefore invariant.
        values = sorted(set(networks(values)) | set(LOOPBACKS))
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
            protected = self._snapshot_protected(db)
            for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                if allowed(row["ip"], values + protected):
                    db.execute("UPDATE bans SET active=0, revoked_at=?,changed_at=? WHERE ip=?", (rev, rev, row["ip"]))
            return self._snapshot(db)
