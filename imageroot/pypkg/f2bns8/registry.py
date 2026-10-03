"""Single authoritative registry. Transactions serialize bans and manual unbans."""

import json
import ipaddress
import time
import uuid
from datetime import datetime, timedelta, timezone
from .common import LOOPBACKS, address, allowed, database, networks, now, safe_text

OFFLINE_LIMIT = timedelta(days=7)


class Registry:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for key, value in (("revision", "0"), ("whitelist_revision", "0"),
                               ("whitelist", '["127.0.0.0/8", "::1/128"]'),
                               ("identity", str(uuid.uuid4())), ("retention_floor", "0")):
                db.execute("INSERT OR IGNORE INTO meta VALUES (?, ?)", (key, value))
            db.execute("CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, active INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL, changed_at INTEGER NOT NULL DEFAULT 0, revoked_on REAL NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, result TEXT NOT NULL, node TEXT NOT NULL DEFAULT '', created_on REAL NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, name TEXT NOT NULL, seen TEXT NOT NULL, revision INTEGER NOT NULL, protected TEXT NOT NULL DEFAULT '[]', rebase_nonce TEXT NOT NULL DEFAULT '')")
            db.execute("CREATE TABLE IF NOT EXISTS policy_revocations (network TEXT PRIMARY KEY, revision INTEGER NOT NULL, created_on REAL NOT NULL DEFAULT 0)")
            db.execute("CREATE INDEX IF NOT EXISTS bans_revoked_on ON bans(revoked_on) WHERE revoked_at>0")
            db.execute("CREATE INDEX IF NOT EXISTS policy_created_on ON policy_revocations(created_on)")
            db.execute("CREATE INDEX IF NOT EXISTS events_created_on ON events(created_on)")

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
                "retention_floor": int(meta["retention_floor"]),
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
                  "retention_floor": int(meta["retention_floor"]),
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

    @staticmethod
    def _prune(db, cutoff):
        db.execute("DELETE FROM events WHERE created_on<?", (cutoff.timestamp(),))
        expired_bans = db.execute(
            "SELECT ip,active,revoked_at FROM bans WHERE revoked_at>0 AND revoked_on<?",
            (cutoff.timestamp(),)).fetchall()
        expired_policies = db.execute(
            "SELECT network,revision FROM policy_revocations WHERE created_on<?",
            (cutoff.timestamp(),)).fetchall()
        floor = max([int(db.execute("SELECT value FROM meta WHERE key='retention_floor'").fetchone()[0])]
                    + [row["revoked_at"] for row in expired_bans]
                    + [row["revision"] for row in expired_policies])
        if expired_bans or expired_policies:
            db.execute("UPDATE meta SET value=? WHERE key='retention_floor'", (str(floor),))
            db.executemany("DELETE FROM bans WHERE ip=?", ((row["ip"],) for row in expired_bans if not row["active"]))
            db.executemany("UPDATE bans SET revoked_at=0,revoked_on=0 WHERE ip=?",
                           ((row["ip"],) for row in expired_bans if row["active"]))
            db.executemany("DELETE FROM policy_revocations WHERE network=?",
                           ((row["network"],) for row in expired_policies))
        return floor

    def sync(self, node, name, revision, identity, events, protected=None, acks=None,
             delta_supported=False, rebase_ack=""):
        uuid.UUID(node)
        if not isinstance(revision, int) or revision < 0 or not isinstance(events, list) or len(events) > 100:
            raise ValueError("Invalid sync request")
        if protected is not None and (not isinstance(protected, list) or len(protected) > 128):
            raise ValueError("Too many protected networks")
        if not isinstance(acks or [], list) or len(acks or []) > 100:
            raise ValueError("Too many acknowledgments")
        if not isinstance(rebase_ack, str) or len(rebase_ack) > 64:
            raise ValueError("Invalid rebase acknowledgment")
        acks = [str(uuid.UUID(item)) for item in (acks or [])]
        protected = networks(protected or [])
        if len(protected) > 128:
            raise ValueError("Too many protected networks after expanding ranges")
        if any(ipaddress.ip_network(value).prefixlen == 0 for value in protected):
            raise ValueError("Protected networks cannot include a default route")
        with database(self.path) as db:
            cutoff = datetime.now(timezone.utc) - OFFLINE_LIMIT
            floor = self._prune(db, cutoff)
            meta = self._meta(db)
            if identity and identity != meta["identity"]:
                raise ValueError("Coordinator identity changed; reconfigure this connection")
            if revision > int(meta["revision"]):
                raise ValueError("Coordinator revision moved backwards; restore its latest database")
            stale_cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat(timespec="seconds")
            stale = db.execute("SELECT id,protected FROM nodes WHERE seen<? AND id!=?",
                               (stale_cutoff, node)).fetchall()
            if stale:
                db.executemany("DELETE FROM events WHERE node=?", ((row["id"],) for row in stale))
                db.executemany("DELETE FROM nodes WHERE id=?", ((row["id"],) for row in stale))
                if any(json.loads(row["protected"]) for row in stale):
                    self._revision(db)
            db.executemany("DELETE FROM events WHERE id=? AND node=?", ((item, node) for item in acks))
            prior = db.execute("SELECT protected,seen,rebase_nonce FROM nodes WHERE id=?", (node,)).fetchone()
            stale_peer = (prior is None or datetime.fromisoformat(prior["seen"]) < cutoff)
            # An old peer must first replace its local state with the current
            # authoritative snapshot. A nonce ensures older module versions
            # cannot replay retained events on the following request.
            nonce = str(uuid.uuid4()) if stale_peer else prior["rebase_nonce"]
            if revision < floor and not nonce:
                nonce = str(uuid.uuid4())
            reset_pending = stale_peer or revision < floor or bool(nonce and rebase_ack != nonce)
            rebased = bool(prior and prior["rebase_nonce"] and rebase_ack == nonce and not reset_pending)
            expired_results = []
            if reset_pending:
                db.execute("DELETE FROM events WHERE node=?", (node,))
                expired_results = [{"id": str(uuid.UUID(event["id"])), "ip": address(event["ip"]),
                                    "result": "expired"} for event in events]
                events = []
            old_protected = json.loads(prior["protected"]) if prior else []
            if protected != old_protected:
                protection_revision = self._revision(db)
                for net in set(protected) - set(old_protected):
                    db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?,?)",
                               (net, protection_revision, time.time()))
            all_protected = sorted({net for row in db.execute("SELECT protected FROM nodes WHERE id!=?", (node,))
                for net in json.loads(row[0])} | set(protected))
            whitelist = json.loads(meta["whitelist"]) + all_protected
            if protected != old_protected:
                for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                    if allowed(row["ip"], whitelist):
                        db.execute("UPDATE bans SET active=0,revoked_at=?,changed_at=?,revoked_on=? WHERE ip=?",
                                   (protection_revision, protection_revision, time.time(), row["ip"]))
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
                try:
                    created = datetime.fromisoformat(event["since"])
                    valid_time = (created.tzinfo is not None and
                        cutoff <= created.astimezone(timezone.utc) <= datetime.now(timezone.utc) + timedelta(minutes=5))
                except (KeyError, TypeError, ValueError):
                    valid_time = False
                if base < floor or not valid_time:
                    verdict = "expired"
                elif allowed(ip, whitelist):
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
                db.execute("INSERT INTO events(id,result,node,created_on) VALUES (?,?,?,?)",
                           (event_id, json.dumps(result), node, time.time()))
                results.append(result)
            db.execute("INSERT INTO nodes(id,name,seen,revision,protected,rebase_nonce) VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,seen=excluded.seen,revision=excluded.revision,protected=excluded.protected,rebase_nonce=excluded.rebase_nonce", (node, safe_text(name, 256), now(), revision, json.dumps(protected), nonce if reset_pending else ""))
            current_revision = int(db.execute("SELECT value FROM meta WHERE key='revision'").fetchone()[0])
            if reset_pending:
                return {**self._snapshot(db), "reset_pending": True, "rebase_nonce": nonce,
                        "results": expired_results}
            if delta_supported and revision == current_revision and protected == old_protected and not results and not rebased:
                return {"identity": meta["identity"], "revision": revision,
                        "retention_floor": floor, "unchanged": True, "results": []}
            if identity and delta_supported:
                return {**self._delta(db, revision), "rebase_nonce": "", "results": results}
            return {**self._snapshot(db), "rebase_nonce": "", "results": results}

    def unban(self, ips):
        if not isinstance(ips, list) or not 1 <= len(ips) <= 1000:
            raise ValueError("Select between 1 and 1000 IPs")
        ips = sorted({address(ip) for ip in ips})
        with database(self.path) as db:
            self._prune(db, datetime.now(timezone.utc) - OFFLINE_LIMIT)
            rev = self._revision(db)
            for ip in ips:
                db.execute("INSERT INTO bans(ip,active,revoked_at,detail,changed_at,revoked_on) VALUES (?,0,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET active=0,revoked_at=excluded.revoked_at,changed_at=excluded.changed_at,revoked_on=excluded.revoked_on", (ip, rev, json.dumps({"ip": ip}), rev, time.time()))
            return self._snapshot(db)

    def set_whitelist(self, values, expected_revision):
        # A host-wide ban on loopback would break the coordinator and other NS8
        # services. These two local-only networks are therefore invariant.
        values = sorted(set(networks(values)) | set(LOOPBACKS))
        with database(self.path) as db:
            self._prune(db, datetime.now(timezone.utc) - OFFLINE_LIMIT)
            meta = self._meta(db)
            if expected_revision != int(meta["whitelist_revision"]):
                raise ValueError("Whitelist changed on another node. Refresh before saving.")
            if values == json.loads(meta["whitelist"]):
                return self._snapshot(db)
            rev = self._revision(db)
            db.execute("UPDATE meta SET value=? WHERE key='whitelist'", (json.dumps(values),))
            db.execute("UPDATE meta SET value=? WHERE key='whitelist_revision'", (str(rev),))
            for net in set(values) - set(json.loads(meta["whitelist"])):
                db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?,?)", (net, rev, time.time()))
            protected = self._snapshot_protected(db)
            for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                if allowed(row["ip"], values + protected):
                    db.execute("UPDATE bans SET active=0, revoked_at=?,changed_at=?,revoked_on=? WHERE ip=?",
                               (rev, rev, time.time(), row["ip"]))
            return self._snapshot(db)
