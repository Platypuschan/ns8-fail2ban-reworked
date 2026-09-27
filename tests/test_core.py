import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import time
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid
from urllib.error import HTTPError

from f2bns8.common import address, allowed, atomic_json, database, networks, public_host
from f2bns8.collector import Collector, owns_record, restore_samba_logging, samba_logging
from f2bns8.node import Node
from f2bns8.registry import Registry
from f2bns8.transport import make_server, request
from f2bns8.firewall import apply as apply_firewall, rules
from f2bns8.notify import message
from f2bns8.parsers import parse
from f2bns8.actions import configure, validate


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = Registry(self.root / "registry.db")
        self.a = Node(self.root / "a.db")
        self.b = Node(self.root / "b.db")
        self.ids = {node: str(uuid.uuid4()) for node in (self.a, self.b)}
        for node in (self.a, self.b):
            node.apply(self.registry.snapshot())
            node.apply(self.registry.sync(self.ids[node], "node", 0,
                                          node.snapshot()["identity"], [], delta_supported=True))
            node.apply(self.registry.sync(self.ids[node], "node", 0,
                                          node.snapshot()["identity"], [],
                                          delta_supported=True, rebase_ack=node.get("rebase_nonce")))

    def tearDown(self):
        self.temp.cleanup()

    def sync(self, node):
        state = node.snapshot()
        result = self.registry.sync(self.ids[node], "NS8 / fail2ban1", state["revision"], state["identity"],
                                    node.pending(), delta_supported=True, rebase_ack=node.get("rebase_nonce", ""))
        node.apply(result)
        return result

    def ban(self, node, ip="198.51.100.23"):
        return node.ban(ip, "sshd", "host", "node", "Failed password for root", True)

    def notifications(self, node):
        with database(node.path) as db:
            return db.execute("SELECT count(*) FROM notifications").fetchone()[0]

    def test_sync_enforces_same_state_without_peer_notifications(self):
        self.ban(self.a)
        self.assertTrue(self.sync(self.a)["delta"])
        self.assertTrue(self.sync(self.b)["delta"])
        self.assertEqual(self.a.bans(), self.b.bans())
        self.assertEqual(self.notifications(self.a), 1)
        self.assertEqual(self.notifications(self.b), 0)
        self.assertFalse(self.a.pending())
        self.assertIsNone(self.ban(self.b))

    def test_offline_cache_and_outbox_survive_restart(self):
        self.ban(self.a)
        restarted = Node(self.a.path)
        self.assertEqual(len(restarted.bans()), 1)
        self.assertEqual(len(restarted.pending()), 1)
        self.sync(self.a)
        self.assertEqual(len(Node(self.a.path).bans()), 1)

    def test_manual_unban_rejects_delayed_events(self):
        self.ban(self.a)
        self.ban(self.b)
        self.sync(self.a)
        self.a.apply(self.registry.unban(["198.51.100.23"]))
        result = self.sync(self.b)
        self.assertEqual(result["results"][0]["result"], "revoked")
        self.assertFalse(self.a.bans())
        self.assertFalse(self.b.bans())
        self.assertEqual(self.notifications(self.b), 0)
        # Fresh failures after the node has learned of the unban can ban again.
        self.ban(self.b)
        self.sync(self.b)
        self.sync(self.a)
        self.assertEqual(len(self.a.bans()), 1)

    def test_manual_unban_clears_local_pending_immediately(self):
        self.ban(self.a)
        self.a.apply(self.registry.unban(["198.51.100.23"]))
        self.assertFalse(self.a.bans())
        self.assertFalse(self.a.pending())

    def test_retries_are_idempotent_even_after_manual_unban(self):
        event = self.ban(self.a)
        s = self.a.snapshot()
        args = (self.ids[self.a], "node", s["revision"], s["identity"], [event])
        first = self.registry.sync(*args)
        second = self.registry.sync(*args)
        self.assertEqual(first["revision"], second["revision"])
        self.registry.unban([event["ip"]])
        self.registry.sync(*args)
        self.assertFalse(self.registry.snapshot()["bans"])

    def test_whitelist_removes_bans_and_wins_over_offline_events(self):
        self.ban(self.a)
        self.ban(self.b)
        self.sync(self.a)
        state = self.registry.set_whitelist(["198.51.100.0/24", "2001:db8::/32"], 0)
        self.a.apply(state)
        self.sync(self.b)
        self.assertFalse(self.a.bans())
        self.assertFalse(self.b.bans())
        self.assertIsNone(self.ban(self.b))
        self.assertIsNone(self.ban(self.b, "2001:db8::1"))

    def test_loopback_can_never_be_removed_from_shared_whitelist(self):
        state = self.registry.set_whitelist([], 0)
        self.assertEqual(state["whitelist"], ["127.0.0.0/8", "::1/128"])
        self.a.apply(state)
        self.assertIsNone(self.ban(self.a, "127.0.0.2"))
        self.assertIsNone(self.ban(self.a, "::1"))

    def test_add_then_remove_whitelist_does_not_resurrect_old_bans(self):
        self.ban(self.b)
        state = self.registry.set_whitelist(["198.51.100.0/24"], 0)
        self.registry.set_whitelist([], state["whitelist_revision"])
        self.sync(self.b)
        self.assertFalse(self.b.bans())

    def test_unrelated_whitelist_change_does_not_drop_offline_ban(self):
        self.ban(self.b)
        self.registry.set_whitelist(["10.0.0.0/8"], 0)
        self.sync(self.b)
        self.assertEqual(len(self.b.bans()), 1)

    def test_concurrent_whitelist_edit_requires_refresh(self):
        self.registry.set_whitelist(["10.0.0.0/8"], 0)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.registry.set_whitelist([], 0)

    def test_concurrent_duplicate_bans_create_one_shared_record(self):
        events = [self.ban(node) for node in (self.a, self.b)]
        state = self.a.snapshot()
        def submit(i):
            return self.registry.sync(self.ids[(self.a, self.b)[i]], str(i), 0, state["identity"], [events[i]])
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            list(pool.map(submit, (0, 1)))
        self.assertEqual(len(self.registry.snapshot()["bans"]), 1)
        self.assertEqual(self.registry.snapshot()["revision"], 1)

    def test_acknowledged_events_are_removed_without_losing_revocation_guard(self):
        event = self.ban(self.a)
        self.sync(self.a)
        ids = self.a.acknowledgments()
        self.assertEqual(ids, [event["id"]])
        state = self.a.snapshot()
        self.registry.sync(self.ids[self.a], "node", state["revision"], state["identity"], [], acks=ids)
        self.a.confirm_acknowledgments(ids)
        with database(self.registry.path, write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 0)
        self.registry.unban([event["ip"]])
        result = self.registry.sync(self.ids[self.a], "node", state["revision"], state["identity"], [event])
        self.assertEqual(result["results"][0]["result"], "revoked")

    def test_unacknowledged_event_records_expire_after_one_week(self):
        self.ban(self.a)
        self.sync(self.a)
        with database(self.registry.path) as db:
            db.execute("UPDATE events SET created_on=?", (time.time() - 8 * 86400,))
        self.sync(self.b)
        with database(self.registry.path, write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 0)
        self.assertEqual(len(self.registry.snapshot()["bans"]), 1)

    def test_protected_peer_address_revokes_a_ban_on_all_nodes(self):
        self.ban(self.a)
        self.sync(self.a)
        state = self.b.snapshot()
        protected = ["198.51.100.23/32", "10.5.4.0/24"]
        result = self.registry.sync(self.ids[self.b], "peer", state["revision"], state["identity"], [], protected)
        self.b.apply(result)
        self.sync(self.a)
        self.assertFalse(self.a.bans())
        self.assertFalse(self.b.bans())
        self.assertIn("10.5.4.0/24", result["protected"])
        self.assertIsNone(self.ban(self.a))

    def test_unchanged_sync_has_no_full_snapshot(self):
        result = self.sync(self.a)
        self.assertTrue(result["unchanged"])
        self.assertNotIn("bans", result)
        state = self.a.snapshot()
        legacy = self.registry.sync(self.ids[self.a], "old peer", state["revision"], state["identity"], [])
        self.assertIn("bans", legacy)

    def test_local_address_is_protected_before_first_sync(self):
        with patch("f2bns8.node.protected_networks", return_value=["198.51.100.23/32"]):
            self.assertIsNone(self.ban(self.a))

    def test_legacy_event_rows_are_migrated_without_permanent_growth(self):
        path = self.root / "legacy.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE events (id TEXT PRIMARY KEY, result TEXT NOT NULL)")
            db.execute("INSERT INTO events VALUES (?,?)", (str(uuid.uuid4()), '{}'))
        Registry(path)
        with database(path, write=False) as db:
            self.assertIn("node", [row[1] for row in db.execute("PRAGMA table_info(events)")])
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 0)

    def test_existing_revocation_markers_get_a_full_week_after_upgrade(self):
        path = self.root / "upgrade.db"
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE bans (ip TEXT PRIMARY KEY, active INTEGER NOT NULL, "
                       "revoked_at INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL, "
                       "changed_at INTEGER NOT NULL DEFAULT 0)")
            db.execute("INSERT INTO bans VALUES ('198.51.100.24',0,2,'{}',2)")
            db.execute("CREATE TABLE policy_revocations (network TEXT PRIMARY KEY, revision INTEGER NOT NULL)")
            db.execute("INSERT INTO policy_revocations VALUES ('198.51.100.0/24',3)")
        Registry(path)
        with database(path, write=False) as db:
            self.assertGreater(db.execute("SELECT revoked_on FROM bans").fetchone()[0], time.time() - 60)
            self.assertGreater(db.execute("SELECT created_on FROM policy_revocations").fetchone()[0], time.time() - 60)
            self.assertIn("rebase_nonce", [row[1] for row in db.execute("PRAGMA table_info(nodes)")])

    def test_stale_peer_and_its_unacknowledged_events_are_pruned(self):
        self.ban(self.a)
        self.sync(self.a)
        with database(self.registry.path) as db:
            db.execute("UPDATE nodes SET seen='2020-01-01T00:00:00+00:00' WHERE id=?", (self.ids[self.a],))
        state = self.b.snapshot()
        self.registry.sync(self.ids[self.b], "active peer", state["revision"], state["identity"], [])
        with database(self.registry.path, write=False) as db:
            self.assertFalse(db.execute("SELECT 1 FROM nodes WHERE id=?", (self.ids[self.a],)).fetchone())
            self.assertEqual(db.execute("SELECT count(*) FROM events WHERE node=?", (self.ids[self.a],)).fetchone()[0], 0)

    def test_one_week_revocation_retention_rebases_old_peer(self):
        self.ban(self.a)
        self.ban(self.b)
        self.sync(self.a)
        self.registry.unban(["198.51.100.23"])
        with database(self.registry.path) as db:
            db.execute("UPDATE bans SET revoked_on=? WHERE ip=?", (time.time() - 8 * 86400, "198.51.100.23"))
        result = self.sync(self.b)
        self.assertTrue(result["reset_pending"])
        self.assertFalse(self.b.pending())
        self.assertFalse(self.b.bans())
        self.assertEqual(self.notifications(self.b), 0)
        with database(self.registry.path, write=False) as db:
            self.assertFalse(db.execute("SELECT 1 FROM bans WHERE ip=?", ("198.51.100.23",)).fetchone())
        self.assertGreaterEqual(result["retention_floor"], 2)
        self.ban(self.b, "198.51.100.24")
        self.sync(self.b)
        self.assertEqual([row["ip"] for row in self.registry.snapshot()["bans"]], ["198.51.100.24"])

    def test_old_whitelist_history_does_not_resurrect_offline_ban(self):
        self.ban(self.b)
        state = self.registry.set_whitelist(["198.51.100.0/24"], 0)
        self.registry.set_whitelist([], state["whitelist_revision"])
        with database(self.registry.path) as db:
            db.execute("UPDATE policy_revocations SET created_on=?", (time.time() - 8 * 86400,))
        result = self.sync(self.b)
        self.assertTrue(result["reset_pending"])
        self.assertFalse(self.registry.snapshot()["bans"])
        with database(self.registry.path, write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM policy_revocations").fetchone()[0], 0)

    def test_peer_offline_over_one_week_discards_local_outbox(self):
        self.ban(self.b)
        with database(self.registry.path) as db:
            db.execute("UPDATE nodes SET seen=? WHERE id=?",
                       ((datetime.now(timezone.utc) - timedelta(days=8)).isoformat(), self.ids[self.b]))
        result = self.sync(self.b)
        self.assertTrue(result["reset_pending"])
        self.assertFalse(self.b.pending())
        self.assertFalse(self.b.bans())
        self.assertEqual(self.notifications(self.b), 0)

    def test_old_peer_cannot_replay_without_acknowledging_rebase(self):
        event = self.ban(self.b)
        state = self.b.snapshot()
        with database(self.registry.path) as db:
            db.execute("UPDATE nodes SET seen=? WHERE id=?",
                       ((datetime.now(timezone.utc) - timedelta(days=8)).isoformat(), self.ids[self.b]))
        first = self.registry.sync(self.ids[self.b], "old peer", state["revision"],
                                   state["identity"], [event])
        second = self.registry.sync(self.ids[self.b], "old peer", state["revision"],
                                    state["identity"], [event])
        self.assertTrue(first["reset_pending"])
        self.assertTrue(second["reset_pending"])
        self.assertEqual(second["results"][0]["result"], "expired")
        self.assertFalse(self.registry.snapshot()["bans"])
        self.b.apply(first)
        self.assertEqual(self.b.get("rebase_nonce"), first["rebase_nonce"])
        self.sync(self.b)
        self.assertEqual(self.b.get("rebase_nonce"), "")
        self.ban(self.b)
        self.sync(self.b)
        self.assertEqual(len(self.registry.snapshot()["bans"]), 1)

    def test_events_older_than_one_week_expire_for_connected_peer(self):
        event = self.ban(self.b)
        event["since"] = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        with database(self.b.path) as db:
            db.execute("UPDATE pending SET event=? WHERE id=?", (json.dumps(event), event["id"]))
        result = self.sync(self.b)
        self.assertEqual(result["results"][0]["result"], "expired")
        self.assertFalse(self.b.pending())
        self.assertEqual(self.notifications(self.b), 0)

    def test_coordinator_identity_and_rollback_are_detected(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            self.registry.sync(self.ids[self.a], "x", 0, "different", [])
        with self.assertRaisesRegex(ValueError, "backwards"):
            self.registry.sync(self.ids[self.a], "x", 99, self.a.snapshot()["identity"], [])

    def test_out_of_order_responses_never_rollback_cache(self):
        self.ban(self.a)
        old = self.sync(self.a)
        self.a.apply(self.registry.unban(["198.51.100.23"]))
        self.a.apply(old)
        self.assertFalse(self.a.bans())


class ApiTests(unittest.TestCase):
    setUp = RegistryTests.setUp
    tearDown = RegistryTests.tearDown

    def test_authenticated_api(self):
        server = make_server(self.registry, "a" * 43)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:" + str(server.server_port)
            with self.assertRaises(HTTPError) as error:
                request(base, "wrong", "/v1/state")
            self.assertEqual(error.exception.code, 401)
            self.assertEqual(request(base, "a" * 43, "/v1/state")["revision"], 0)
            self.assertEqual(request(base, "a" * 43, "/v1/unban", {"ips": ["198.51.100.23"]})["revision"], 1)
        finally:
            server.shutdown()
            server.server_close()

    def test_failed_token_attempts_are_limited_without_blocking_peers(self):
        server = make_server(self.registry, "a" * 43)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:" + str(server.server_port)
            for _ in range(20):
                with self.assertRaises(HTTPError) as error:
                    request(base, "wrong", "/v1/state")
                self.assertEqual(error.exception.code, 401)
            with self.assertRaises(HTTPError) as error:
                request(base, "wrong", "/v1/state")
            self.assertEqual(error.exception.code, 429)
            self.assertEqual(request(base, "a" * 43, "/v1/state")["revision"], 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_large_snapshot_is_paged_and_reassembled(self):
        class LargeRegistry:
            @staticmethod
            def snapshot():
                return {"identity": "test", "revision": 4, "bans": [{"ip": "198.51.100.1", "note": "x" * 1024}] * 2300}
        server = make_server(LargeRegistry(), "a" * 43)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            state = request("http://127.0.0.1:" + str(server.server_port), "a" * 43, "/v1/state")
            self.assertEqual(len(state["bans"]), 2300)
            self.assertEqual(state["revision"], 4)
        finally:
            server.shutdown()
            server.server_close()


class ParserTests(unittest.TestCase):
    def test_ssh_invalid_user_and_maximum_attempts(self):
        self.assertEqual(parse("sshd", "Invalid user admin from 198.51.100.7 port 2222"), "198.51.100.7")
        self.assertEqual(parse("sshd", "Connection closed by invalid user admin 198.51.100.7 port 2222 [preauth]"), "198.51.100.7")
        self.assertEqual(parse("sshd", "maximum authentication attempts exceeded for invalid user admin from 198.51.100.7 port 2222 ssh2 [preauth]"), "198.51.100.7")
        self.assertIsNone(parse("sshd", "Connection closed by 198.51.100.7 port 2222 [preauth]"))

    def test_ssh_cannot_inject_a_victim_ip_through_username(self):
        raw = "Failed password for invalid user pretend from 203.0.113.99 port 1 ssh2 from 198.51.100.2 port 4200 ssh2"
        self.assertEqual(parse("sshd", raw), "198.51.100.2")
        self.assertIsNone(parse("sshd", "Accepted password for root from 198.51.100.2 port 42 ssh2"))

    def test_ipv6_and_mapped_addresses(self):
        self.assertEqual(parse("sshd", "Failed password for root from 2001:db8::1 port 5 ssh2"), "2001:db8::1")
        self.assertEqual(address("::ffff:192.0.2.1"), "192.0.2.1")

    def test_gitea_login_failure_not_key_probe(self):
        self.assertEqual(parse("gitea", "2026-01-01 [W] Failed authentication attempt for alice from 198.51.100.3:3311"), "198.51.100.3")
        self.assertIsNone(parse("gitea", "publicKeyHandler() invalid credentials from 198.51.100.3"))
        self.assertEqual(parse("gitea", "2026/09/23 auth.go:231:SignInPost() [W] Failed authentication attempt for alice from 198.51.100.3:3311: user does not exist [uid: 0, name: alice]"), "198.51.100.3")
        self.assertIsNone(parse("gitea", "2026/09/23 auth.go:231:SignInPost() [W] Failed authentication attempt for forged [W] invalid credentials from 203.0.113.99: from 198.51.100.3:3311: bad user"))

    def test_organizr_json_field_not_attacker_text(self):
        raw = {"channel": "Authentication", "message": "Wrong Password", "remote_ip_address": "198.51.100.4", "username": "from 203.0.113.99"}
        self.assertEqual(parse("organizr", json.dumps(raw)), "198.51.100.4")
        raw["message"] = "User exceeded maximum login attempts"
        self.assertIsNone(parse("organizr", json.dumps(raw)))

    def test_samba_failure_vs_success_and_non_address(self):
        raw = {"type": "Authentication", "Authentication": {"status": "NT_STATUS_LOGON_FAILURE", "remoteAddress": "ipv4:198.51.100.5:42000"}}
        self.assertEqual(parse("samba", json.dumps(raw)), "198.51.100.5")
        raw["Authentication"]["status"] = "NT_STATUS_OK"
        self.assertIsNone(parse("samba", json.dumps(raw)))
        raw["Authentication"].update(status="NT_STATUS_WRONG_PASSWORD", remoteAddress="unix:/tmp/socket")
        self.assertIsNone(parse("samba", json.dumps(raw)))

    def test_ns8_login_only_on_ns8_router(self):
        line = '198.51.100.6 - - [23/Sep/2026:12:00:00 +0000] "POST /cluster-admin/api/login HTTP/2.0" 401 52 "-" "Firefox" 1 "cluster-admin-https@file" "http://127.0.0.1:9311" 2ms'
        self.assertEqual(parse("ns8", line), "198.51.100.6")
        self.assertEqual(parse("ns8", line + "\n"), "198.51.100.6")
        self.assertIsNone(parse("ns8", line.replace("401", "200")))
        self.assertIsNone(parse("ns8", line.replace("cluster-admin-https@file", "myapp@file")))
        self.assertIsNone(parse("ns8", line.replace("/api/login", "/api/users")))
        self.assertEqual(parse("ns8", line.replace('"Firefox"', '"forged \\" POST /cluster-admin/api/login HTTP/1.1"')), "198.51.100.6")


class CollectorTests(unittest.TestCase):
    def test_samba_live_audit_level_is_restored_on_removal(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"F2B_STATE_DIR": directory}), \
                patch("f2bns8.collector.run_module") as run, \
                patch("f2bns8.collector.subprocess.run") as process:
            samba_logging({"module": "samba1", "environment": {"SAMBA_LOGLEVEL": "1 auth_json_audit:0"}})
            self.assertNotIn("set_env", str(run.call_args_list))
            self.assertIn("auth_json_audit:2", str(run.call_args))
            process.return_value.returncode = 0
            process.return_value.stdout = "samba-dc\n"
            restore_samba_logging()
            self.assertIn("1 auth_json_audit:0", str(run.call_args))
            self.assertFalse((Path(directory) / "samba-levels.json").exists())

    def test_one_ssh_connection_does_not_count_multiple_log_lines(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"F2B_STATE_DIR": directory}):
            collector = Collector()
            messages = [
                "Invalid user admin from 198.51.100.7 port 4444",
                "Failed password for invalid user admin from 198.51.100.7 port 4444 ssh2",
                "Connection closed by invalid user admin 198.51.100.7 port 4444 [preauth]",
            ]
            with patch.object(collector, "emit") as emit:
                for message in messages:
                    collector.journal({"_SYSTEMD_UNIT": "sshd@1.service", "_PID": "42",
                        "MESSAGE": message, "__REALTIME_TIMESTAMP": str(int(datetime.now(timezone.utc).timestamp() * 1000000))})
            self.assertEqual(emit.call_count, 1)

    def test_rootful_samba_and_exact_module_boundary(self):
        samba = {"module": "samba1", "jail": "samba", "uid": "0", "uid_ranges": [(0, 1)]}
        self.assertTrue(owns_record(samba, {"_UID": "0", "CONTAINER_NAME": "samba-dc"}))
        source = {**samba, "container_id": "a" * 64, "ambiguous_samba": True}
        self.assertTrue(owns_record(source, {"_UID": "0", "CONTAINER_NAME": "samba-dc", "CONTAINER_ID_FULL": "a" * 64}))
        self.assertFalse(owns_record(source, {"_UID": "0", "CONTAINER_NAME": "samba-dc", "CONTAINER_ID_FULL": "b" * 64}))
        self.assertFalse(owns_record(source, {"_UID": "0", "CONTAINER_NAME": "samba-dc"}))
        other = {**samba, "jail": "gitea"}
        self.assertTrue(owns_record(other, {"_UID": "0", "CONTAINER_NAME": "samba1-app"}))
        self.assertFalse(owns_record(other, {"_UID": "0", "CONTAINER_NAME": "samba10-app"}))

    def test_rootless_container_journal_uses_module_subuids(self):
        source = {"module": "traefik1", "uid": "1001", "uid_ranges": [(1001, 1002), (100000, 165536)]}
        for uid in (1001, 100000, 165535):
            self.assertTrue(owns_record(source, {"_UID": str(uid)}))
        for uid in (0, 1002, 99999, 165536):
            # Container names alone cannot impersonate a different module.
            self.assertFalse(owns_record(source, {"_UID": str(uid), "CONTAINER_NAME": "traefik"}))

    def test_oversized_partial_log_does_not_hide_later_failures(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"F2B_STATE_DIR": directory}):
            root = Path(directory)
            path = root / "organizr.log"
            path.write_bytes(b"x" * 70000)
            collector = Collector()
            collector.files = [({"module": "organizr1"}, path)]
            collector.tail_files()
            atomic_json(root / "collector.json", collector.checkpoint)
            # Collection must resume correctly even after a service restart.
            collector = Collector()
            collector.files = [({"module": "organizr1"}, path)]
            record = {"channel": "Authentication", "message": "Wrong Password",
                "remote_ip_address": "198.51.100.4", "datetime": datetime.now(timezone.utc).isoformat()}
            with path.open("a") as stream:
                stream.write("remaining oversized record\n" + json.dumps(record) + "\n")
            collector.tail_files()
            detected = (root / "logs/organizr.log").read_text().splitlines()
            self.assertEqual(len(detected), 1)
            self.assertIn("198.51.100.4", detected[0])
            self.assertIn("Wrong Password", detected[0])


class ConfigurationTests(unittest.TestCase):
    def test_first_configuration_enrolls_before_collection_can_start(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {
            "F2B_STATE_DIR": directory, "MODULE_ID": "fail2ban1", "TCP_PORT": "20001"}), \
                patch("f2bns8.actions.shutil.which", return_value="/usr/sbin/nft"), \
                patch("f2bns8.actions.local_networks", return_value=[]), \
                patch("f2bns8.actions.protected_networks", return_value=[]), \
                patch("f2bns8.actions.lifecycle.route"), \
                patch("f2bns8.actions.lifecycle.start") as start:
            def collector_wins_startup_race(settings):
                root = Path(directory)
                node = Node(root / "node.sqlite3")
                registry = Registry(root / "coordinator.sqlite3")
                self.assertEqual(node.get("rebase_nonce"), "")
                event = node.ban("198.51.100.23", "sshd", "host", "node", "failure")
                state = node.snapshot()
                result = registry.sync(settings["node_id"], settings["node_name"],
                                       state["revision"], state["identity"], [event])
                self.assertEqual(result["results"][0]["result"], "accepted")
            start.side_effect = collector_wins_startup_race
            configure({"mode": "coordinator", "public_url": "https://bans.example.org"})
            start.assert_called_once()

    def test_first_peer_configuration_aborts_if_enrollment_loses_connection(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {
            "F2B_STATE_DIR": directory, "MODULE_ID": "fail2ban1", "TCP_PORT": "20001"}), \
                patch("f2bns8.actions.shutil.which", return_value="/usr/sbin/nft"), \
                patch("f2bns8.actions.local_networks", return_value=[]), \
                patch("f2bns8.actions.protected_networks", return_value=[]), \
                patch("f2bns8.actions.request", return_value=Registry(Path(directory) / "remote.db").snapshot()), \
                patch("f2bns8.actions.call", side_effect=OSError("coordinator unavailable")), \
                patch("f2bns8.actions.lifecycle.destroy"), \
                patch("f2bns8.actions.lifecycle.start") as start:
            with self.assertRaisesRegex(OSError, "coordinator unavailable"):
                configure({"mode": "peer", "sync_url": "https://bans.example.org",
                           "sync_token": "a" * 43})
            start.assert_not_called()
            self.assertFalse((Path(directory) / "config.json").exists())
            self.assertFalse((Path(directory) / "node.sqlite3").exists())

    def test_first_peer_configuration_finishes_enrollment_before_start(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as remote, \
                patch.dict("os.environ", {"F2B_STATE_DIR": directory, "MODULE_ID": "fail2ban1",
                                          "TCP_PORT": "20001"}), \
                patch("f2bns8.actions.shutil.which", return_value="/usr/sbin/nft"), \
                patch("f2bns8.actions.local_networks", return_value=[]), \
                patch("f2bns8.actions.protected_networks", return_value=[]), \
                patch("f2bns8.actions.lifecycle.start") as start:
            registry = Registry(Path(remote) / "coordinator.db")
            with patch("f2bns8.actions.request", return_value=registry.snapshot()), \
                    patch("f2bns8.actions.call", side_effect=lambda settings, path, data:
                          registry.sync(data["node"], data["name"], data["revision"],
                                        data["identity"], data["events"], data["protected"],
                                        delta_supported=data["delta_supported"],
                                        rebase_ack=data["rebase_ack"])):
                def check_enrollment(settings):
                    self.assertEqual(Node(Path(directory) / "node.sqlite3").get("rebase_nonce"), "")
                    with database(registry.path, write=False) as db:
                        row = db.execute("SELECT rebase_nonce FROM nodes WHERE id=?",
                                         (settings["node_id"],)).fetchone()
                    self.assertIsNotNone(row)
                    self.assertEqual(row[0], "")
                start.side_effect = check_enrollment
                configure({"mode": "peer", "sync_url": "https://bans.example.org",
                           "sync_token": "a" * 43})
                start.assert_called_once()

    def test_first_configuration_failure_cleans_up_written_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {
            "F2B_STATE_DIR": directory, "MODULE_ID": "fail2ban1", "TCP_PORT": "20001"}), \
                patch("f2bns8.actions.shutil.which", return_value="/usr/sbin/nft"), \
                patch("f2bns8.actions.lifecycle.route"), \
                patch("f2bns8.actions.lifecycle.destroy") as destroy, \
                patch("f2bns8.actions.lifecycle.start", side_effect=RuntimeError("start failed")):
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                configure({"mode": "coordinator", "public_url": "https://bans.example.org"})
            destroy.assert_called_once()
            self.assertFalse((Path(directory) / "config.json").exists())
            self.assertFalse((Path(directory) / "node.sqlite3").exists())
            self.assertFalse((Path(directory) / "coordinator.sqlite3").exists())

    def test_whitelist_ranges(self):
        self.assertEqual(networks(["192.0.2.1-192.0.2.2"]), ["192.0.2.1/32", "192.0.2.2/32"])
        self.assertEqual(networks(["192.0.2.17/24"]), ["192.0.2.0/24"])
        self.assertEqual(networks(["::ffff:192.0.2.17/120"]), ["192.0.2.0/24"])
        self.assertEqual(networks(["::ffff:192.0.2.1-::ffff:192.0.2.2"]), ["192.0.2.1/32", "192.0.2.2/32"])
        for value in ("192.0.2.1 # comment", "192.0.2.1;touch /tmp/bad", "fe80::1%eth0"):
            with self.assertRaises(ValueError):
                networks([value])
        self.assertTrue(allowed("198.51.100.2", ["198.51.100.0/24", "2001:db8::/32"]))
        self.assertTrue(allowed("2001:db8::1", ["198.51.100.0/24", "2001:db8::/32"]))
        self.assertFalse(allowed("198.51.101.2", ["198.51.100.0/24", "2001:db8::/32"]))
        self.assertFalse(allowed("2001:db9::1", ["198.51.100.0/24", "2001:db8::/32"]))

    @patch.dict("os.environ", {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_protected_range_limit_applies_after_expansion(self):
        expanded = "2001:db8::1-2001:db8:ffff:ffff:ffff:ffff:ffff:fffe"
        with patch("f2bns8.actions.local_networks", return_value=[]):
            with self.assertRaisesRegex(ValueError, "after expanding"):
                validate({"mode": "coordinator", "public_url": "https://bans.example.org",
                          "protected_networks": [expanded]}, {})
        with tempfile.TemporaryDirectory() as directory:
            registry = Registry(Path(directory) / "registry.db")
            with self.assertRaisesRegex(ValueError, "after expanding"):
                registry.sync(str(uuid.uuid4()), "peer", 0, "", [], [expanded])

    def test_public_url_has_no_database_port(self):
        self.assertEqual(public_host("https://bans.example.org"), "bans.example.org")
        for value in ("http://bans.example.org", "https://bans.example.org:5432", "https://user:pass@bans.example.org", "https://bans.example.org/path"):
            with self.assertRaises(ValueError):
                public_host(value)

    def test_all_ports_protocols_and_directions_without_expiry(self):
        content = rules("fail2ban1", ["198.51.100.3", "2001:db8::3"], True)
        for hook in ("input", "output", "forward"):
            self.assertIn("hook " + hook, content)
        self.assertEqual(content.count(" counter drop"), 8)
        self.assertNotIn("dport", content)
        self.assertNotIn("timeout", content)
        self.assertNotIn("ct state", content)
        self.assertNotIn("flush ruleset", content)
        with self.assertRaises(ValueError):
            rules("fail2ban1", ["1.2.3.4; flush ruleset"], True)

    def test_firewall_recreates_a_damaged_existing_table(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("f2bns8.firewall.state_dir", return_value=Path(directory)), \
                patch("f2bns8.firewall.subprocess.run") as command:
            command.side_effect = [
                type("Result", (), {"returncode": 0, "stdout": "table inet damaged { set banned4 { type ipv4_addr; } }"})(),
                type("Result", (), {"returncode": 0})(),
            ]
            apply_firewall("fail2ban1", ["198.51.100.1"])
            batch = command.call_args_list[1].kwargs["input"]
            self.assertIn("delete table inet ns8_f2b_", batch)
            self.assertIn("add chain inet ns8_f2b_", batch)
            self.assertIn("198.51.100.1", batch)

    @patch.dict("os.environ", {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_settings_keep_tokens_without_echoing_them(self):
        settings = validate({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {"enabled": False}}, {})
        self.assertGreaterEqual(len(settings["sync_token"]), 32)
        self.assertEqual(validate({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {}}, settings)["sync_token"], settings["sync_token"])
        settings["notifications"]["token"] = "saved-token"
        self.assertEqual(validate({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {}}, settings)["notifications"]["token"], "saved-token")

    def test_notification_has_all_requested_fields(self):
        body = message({"ip": "198.51.100.2", "since": "2026-09-23T12:00:00Z", "jail": "gitea", "node": "example-node", "module": "example-module", "matches": "Wrong password"})
        for item in ("198.51.100.2", "2026-09-23T12:00:00Z", "gitea", "example-node", "example-module", "Wrong password"):
            self.assertIn(item, body)


if __name__ == "__main__":
    unittest.main()
