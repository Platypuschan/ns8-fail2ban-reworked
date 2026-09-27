"""Single authoritative registry. Transactions serialize bans and manual unbans."""

import json
import ipaddress
import time
import uuid
from datetime import datetime, timedelta, timezone
from .common import address, allowed, database, networks, now, safe_text, shared_whitelist


class Registry:
    def __init__(self, path):
        self.path = path
        with database(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for key, value in (("revision", "0"), ("whitelist_revision", "0"),
                               ("whitelist", '["127.0.0.0/8", "::1/128"]'),
                               ("identity", str(uuid.uuid4())),
                               ("generation", str(uuid.uuid4()))):
                db.execute("INSERT OR IGNORE INTO meta VALUES (?, ?)", (key, value))
            db.execute("CREATE TABLE IF NOT EXISTS bans (ip TEXT PRIMARY KEY, active INTEGER NOT NULL, revoked_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, result TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, name TEXT NOT NULL, seen TEXT NOT NULL, revision INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS protected (node TEXT NOT NULL, network TEXT NOT NULL, PRIMARY KEY(node,network))")
            db.execute("CREATE TABLE IF NOT EXISTS policy_revocations (network TEXT PRIMARY KEY, revision INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS changes (revision INTEGER PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL)")
            for table, column in (("events", "created"), ("bans", "revoked_time"),
                                  ("policy_revocations", "created")):
                if column not in [row[1] for row in db.execute(f"PRAGMA table_info({table})")]:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {column} REAL NOT NULL DEFAULT 0")
                    # Existing rows have no timestamp; allow a full retention
                    # period before removing their replay protection.
                    db.execute(f"UPDATE {table} SET {column}=?", (time.time(),))
            revision = int(db.execute("SELECT value FROM meta WHERE key='revision'").fetchone()[0])
            for key, value in (("delta_floor", str(revision)), ("history_floor", "0"),
                               ("protected_revision", "0"), ("last_prune", "0")):
                db.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", (key, value))

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
        return {"identity": meta["identity"], "generation": meta["generation"],
                "revision": int(meta["revision"]),
                "history_floor": int(meta["history_floor"]),
                "whitelist_revision": int(meta["whitelist_revision"]),
                "whitelist": json.loads(meta["whitelist"]),
                "protected": sorted({r[0] for r in db.execute("SELECT network FROM protected")}),
                "revocations": dict(db.execute("SELECT ip,revoked_at FROM bans WHERE revoked_at>0")),
                "policy_revocations": dict(db.execute("SELECT network,revision FROM policy_revocations")),
                "bans": [json.loads(r[0]) for r in db.execute("SELECT detail FROM bans WHERE active=1 ORDER BY ip")],
                "nodes": [dict(r) for r in db.execute("SELECT name,seen,revision FROM nodes ORDER BY name")]}

    def snapshot(self):
        with database(self.path, readonly=True) as db:
            return self._snapshot(db)

    def new_generation(self):
        """Mark a restored database so peers accept its older revision."""
        with database(self.path) as db:
            db.execute("UPDATE meta SET value=? WHERE key='generation'", (str(uuid.uuid4()),))

    @staticmethod
    def _change(db, revision, **payload):
        db.execute("INSERT INTO changes VALUES (?,?,?)", (revision, json.dumps(payload), time.time()))

    def _response(self, db, revision, generation, results, protocol=None):
        meta = self._meta(db)
        current = int(meta["revision"])
        if protocol != 2 or generation != meta["generation"] or revision < int(meta["delta_floor"]):
            return {**self._snapshot(db), "results": results}
        upserts, removals = {}, set()
        for row in db.execute("SELECT payload FROM changes WHERE revision>? ORDER BY revision", (revision,)):
            change = json.loads(row[0])
            for ip in change.get("removals", []):
                upserts.pop(ip, None)
                removals.add(ip)
            for ban in change.get("upserts", []):
                upserts[ban["ip"]] = ban
                removals.discard(ban["ip"])
        result = {"delta": True, "base_revision": revision,
                  "identity": meta["identity"], "generation": meta["generation"],
                  "revision": current, "history_floor": int(meta["history_floor"]),
                  "whitelist_revision": int(meta["whitelist_revision"]),
                  "upserts": list(upserts.values()), "removals": sorted(removals), "results": results,
                  "revocations": dict(db.execute("SELECT ip,revoked_at FROM bans WHERE revoked_at>?", (revision,))),
                  "policy_revocations": dict(db.execute("SELECT network,revision FROM policy_revocations WHERE revision>?", (revision,)))}
        if int(meta["whitelist_revision"]) > revision:
            result["whitelist"] = json.loads(meta["whitelist"])
        if int(meta["protected_revision"]) > revision:
            result["protected"] = sorted({r[0] for r in db.execute("SELECT network FROM protected")})
        return result

    def _prune(self, db):
        meta = self._meta(db)
        at = time.time()
        if at - float(meta["last_prune"]) < 3600:
            return
        revision = int(meta["revision"])
        db.execute("DELETE FROM events WHERE created<? OR rowid IN "
                   "(SELECT rowid FROM events ORDER BY rowid DESC LIMIT -1 OFFSET 20000)", (at - 30 * 86400,))
        rows = db.execute("SELECT revision FROM changes WHERE created<? OR revision<=?",
                          (at - 7 * 86400, revision - 20000)).fetchall()
        if rows:
            floor = max(int(meta["delta_floor"]), max(row[0] for row in rows))
            db.execute("DELETE FROM changes WHERE created<? OR revision<=?", (at - 7 * 86400, revision - 20000))
            db.execute("UPDATE meta SET value=? WHERE key='delta_floor'", (str(floor),))
        expired = db.execute("SELECT revoked_at FROM bans WHERE revoked_at>0 AND (revoked_time<? OR revoked_at<=?)",
                             (at - 30 * 86400, revision - 20000)).fetchall()
        policies = db.execute("SELECT revision FROM policy_revocations WHERE created<? OR revision<=?",
                              (at - 30 * 86400, revision - 20000)).fetchall()
        if expired or policies:
            floor = max([int(meta["history_floor"])] + [row[0] for row in expired + policies])
            db.execute("DELETE FROM bans WHERE active=0 AND revoked_at>0 AND (revoked_time<? OR revoked_at<=?)",
                       (at - 30 * 86400, revision - 20000))
            db.execute("UPDATE bans SET revoked_at=0,revoked_time=0 WHERE active=1 AND revoked_at>0 AND (revoked_time<? OR revoked_at<=?)",
                       (at - 30 * 86400, revision - 20000))
            db.execute("DELETE FROM policy_revocations WHERE created<? OR revision<=?",
                       (at - 30 * 86400, revision - 20000))
            db.execute("UPDATE meta SET value=? WHERE key='history_floor'", (str(floor),))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
        db.execute("DELETE FROM nodes WHERE seen<?", (cutoff,))
        removed = db.execute("DELETE FROM protected WHERE node NOT IN (SELECT id FROM nodes)").rowcount
        if removed:
            changed = self._revision(db)
            self._change(db, changed, removals=[])
            db.execute("UPDATE meta SET value=? WHERE key='protected_revision'", (str(changed),))
        db.execute("UPDATE meta SET value=? WHERE key='last_prune'", (str(at),))

    def sync(self, node, name, revision, identity, events, generation=None, protected=None, protocol=None):
        uuid.UUID(node)
        if not isinstance(revision, int) or revision < 0 or not isinstance(events, list) or len(events) > 100:
            raise ValueError("Invalid sync request")
        if protected is not None:
            if not isinstance(protected, list) or len(protected) > 4096:
                raise ValueError("Too many protected networks")
            protected = networks(protected)
            if len(protected) > 4096:
                raise ValueError("Too many protected networks")
        if not events:
            with database(self.path, readonly=True) as db:
                meta = self._meta(db)
                seen = db.execute("SELECT seen FROM nodes WHERE id=?", (node,)).fetchone()
                if (identity in ("", meta["identity"]) and revision <= int(meta["revision"])
                        and generation == meta["generation"] and seen
                        and time.time() - float(meta["last_prune"]) < 3600
                        and (protected is None or protected == sorted(r[0] for r in
                            db.execute("SELECT network FROM protected WHERE node=?", (node,))))
                        and (datetime.now(timezone.utc) - datetime.fromisoformat(seen[0])).total_seconds() < 60):
                    return self._response(db, revision, generation, [], protocol)
        with database(self.path) as db:
            self._prune(db)
            meta = self._meta(db)
            if identity and identity != meta["identity"]:
                raise ValueError("Coordinator identity changed; reconfigure this connection")
            # Peers without a generation predate restore support.
            restored = generation is not None and generation != meta["generation"]
            if revision > int(meta["revision"]) and not restored:
                raise ValueError("Coordinator revision moved backwards; restore its latest database")
            if protected is not None:
                previous = {r[0] for r in db.execute("SELECT network FROM protected WHERE node=?", (node,))}
                if previous != set(protected):
                    db.execute("DELETE FROM protected WHERE node=?", (node,))
                    db.executemany("INSERT INTO protected VALUES (?,?)", [(node, net) for net in protected])
                    changed = self._revision(db)
                    db.execute("UPDATE meta SET value=? WHERE key='protected_revision'", (str(changed),))
                    for net in set(protected) - previous:
                        db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?,?)", (net, changed, time.time()))
                    all_protected = [r[0] for r in db.execute("SELECT DISTINCT network FROM protected")]
                    removals = []
                    for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                        if allowed(row["ip"], all_protected):
                            removals.append(row["ip"])
                            db.execute("UPDATE bans SET active=0,revoked_at=?,revoked_time=? WHERE ip=?",
                                       (changed, time.time(), row["ip"]))
                    self._change(db, changed, removals=removals)
                    meta = self._meta(db)
            results = []
            policy = [(ipaddress.ip_network(net), rev) for net, rev in
                      db.execute("SELECT network,revision FROM policy_revocations")]
            protection = json.loads(meta["whitelist"]) + [r[0] for r in db.execute("SELECT network FROM protected")]
            # A peer from another generation first adopts this snapshot, which
            # rebases its outbox, and submits its events on the next sync.
            for event in [] if restored else events:
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
                if allowed(ip, protection):
                    verdict = "whitelisted"
                elif base < int(meta["history_floor"]):
                    verdict = "stale"
                elif (row and row["revoked_at"] > base) or any(
                    rev > base and ipaddress.ip_address(ip) in net for net, rev in policy):
                    verdict = "revoked"
                elif row and row["active"]:
                    verdict = "already-banned"
                else:
                    detail = {"ip": ip, "since": safe_text(event.get("since", now()), 64),
                              "jail": safe_text(event["jail"], 128), "node": safe_text(name, 256),
                              "module": safe_text(event.get("module", ""), 128)}
                    db.execute("INSERT INTO bans(ip,active,revoked_at,detail) VALUES (?,1,0,?) "
                               "ON CONFLICT(ip) DO UPDATE SET active=1, detail=excluded.detail", (ip, json.dumps(detail)))
                    changed = self._revision(db)
                    self._change(db, changed, upserts=[detail])
                result = {"id": event_id, "ip": ip, "result": verdict}
                db.execute("INSERT INTO events(id,result,created) VALUES (?,?,?)", (event_id, json.dumps(result), time.time()))
                results.append(result)
            db.execute("INSERT INTO nodes VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,seen=excluded.seen,revision=excluded.revision", (node, safe_text(name, 256), now(), revision))
            return self._response(db, revision, generation, results, protocol)

    def unban(self, ips):
        if not isinstance(ips, list) or not 1 <= len(ips) <= 1000:
            raise ValueError("Select between 1 and 1000 IPs")
        ips = sorted({address(ip) for ip in ips})
        with database(self.path) as db:
            rev = self._revision(db)
            for ip in ips:
                db.execute("INSERT INTO bans(ip,active,revoked_at,detail,revoked_time) VALUES (?,0,?,?,?) "
                           "ON CONFLICT(ip) DO UPDATE SET active=0,revoked_at=excluded.revoked_at,revoked_time=excluded.revoked_time",
                           (ip, rev, json.dumps({"ip": ip}), time.time()))
            self._change(db, rev, removals=ips)
            return self._snapshot(db)

    def set_whitelist(self, values, expected_revision):
        values = shared_whitelist(values)
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
                db.execute("INSERT OR REPLACE INTO policy_revocations VALUES (?,?,?)", (net, rev, time.time()))
            removals = []
            for row in db.execute("SELECT ip FROM bans WHERE active=1").fetchall():
                if allowed(row["ip"], values):
                    db.execute("UPDATE bans SET active=0, revoked_at=?, revoked_time=? WHERE ip=?", (rev, time.time(), row["ip"]))
                    removals.append(row["ip"])
            self._change(db, rev, removals=removals)
            return self._snapshot(db)
