import concurrent.futures
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid
from urllib.error import HTTPError

from f2bns8.common import address, database, networks, public_host
from f2bns8.node import Node
from f2bns8.registry import Registry
from f2bns8.transport import make_server, request
from f2bns8.firewall import rules
from f2bns8.notify import message
from f2bns8.parsers import parse
from f2bns8.actions import validate


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

    def tearDown(self):
        self.temp.cleanup()

    def sync(self, node):
        state = node.snapshot()
        result = self.registry.sync(self.ids[node], "NS8 / fail2ban1", state["revision"], state["identity"], node.pending())
        node.apply(result)
        return result

    def ban(self, node, ip="198.51.100.23"):
        return node.ban(ip, "sshd", "host", "node", "Failed password for root", True)

    def notifications(self, node):
        with database(node.path) as db:
            return db.execute("SELECT count(*) FROM notifications").fetchone()[0]

    def test_sync_enforces_same_state_without_peer_notifications(self):
        self.ban(self.a)
        self.sync(self.a)
        self.sync(self.b)
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
        self.assertFalse(self.registry.sync(*args)["bans"])

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
            return self.registry.sync(str(uuid.uuid4()), str(i), 0, state["identity"], [events[i]])
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            list(pool.map(submit, (0, 1)))
        self.assertEqual(len(self.registry.snapshot()["bans"]), 1)
        self.assertEqual(self.registry.snapshot()["revision"], 1)

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


class ParserTests(unittest.TestCase):
    def test_ssh_cannot_inject_a_victim_ip_through_username(self):
        raw = "Failed password for invalid user pretend from 203.0.113.99 port 1 ssh2 from 198.51.100.2 port 4200 ssh2"
        self.assertEqual(parse("sshd", raw), "198.51.100.2")
        self.assertIsNone(parse("sshd", "Accepted password for root from 198.51.100.2 port 42 ssh2"))

    def test_ipv6_and_mapped_addresses(self):
        self.assertEqual(parse("sshd", "Failed password for root from 2001:db8::1 port 5 ssh2"), "2001:db8::1")
        self.assertEqual(address("::ffff:192.0.2.1"), "192.0.2.1")

    def test_gitea_login_failure_not_key_probe(self):
        self.assertEqual(parse("gitea", "2026-01-01 [W] Failed authentication attempt for arne from 198.51.100.3:3311"), "198.51.100.3")
        self.assertIsNone(parse("gitea", "publicKeyHandler() invalid credentials from 198.51.100.3"))
        self.assertEqual(parse("gitea", "2026/09/23 auth.go:231:SignInPost() [W] Failed authentication attempt for arne from 198.51.100.3:3311: user does not exist [uid: 0, name: arne]"), "198.51.100.3")
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
        self.assertIsNone(parse("ns8", line.replace("401", "200")))
        self.assertIsNone(parse("ns8", line.replace("cluster-admin-https@file", "myapp@file")))
        self.assertIsNone(parse("ns8", line.replace("/api/login", "/api/users")))
        self.assertEqual(parse("ns8", line.replace('"Firefox"', '"forged \\" POST /cluster-admin/api/login HTTP/1.1"')), "198.51.100.6")


class ConfigurationTests(unittest.TestCase):
    def test_whitelist_ranges(self):
        self.assertEqual(networks(["192.0.2.1-192.0.2.2"]), ["192.0.2.1/32", "192.0.2.2/32"])
        self.assertEqual(networks(["192.0.2.17/24"]), ["192.0.2.0/24"])
        for value in ("192.0.2.1 # comment", "192.0.2.1;touch /tmp/bad", "fe80::1%eth0"):
            with self.assertRaises(ValueError):
                networks([value])

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

    @patch.dict("os.environ", {"MODULE_ID": "fail2ban1", "TCP_PORT": "20001"})
    def test_settings_keep_tokens_without_echoing_them(self):
        settings = validate({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {"enabled": False}}, {})
        self.assertGreaterEqual(len(settings["sync_token"]), 32)
        self.assertEqual(validate({"mode": "coordinator", "public_url": "https://bans.example.org", "notifications": {}}, settings)["sync_token"], settings["sync_token"])

    def test_notification_has_all_requested_fields(self):
        body = message({"ip": "198.51.100.2", "since": "2026-09-23T12:00:00Z", "jail": "gitea", "node": "ns8-home", "module": "gitea1", "matches": "Wrong password"})
        for item in ("198.51.100.2", "2026-09-23T12:00:00Z", "gitea", "ns8-home", "gitea1", "Wrong password"):
            self.assertIn(item, body)


if __name__ == "__main__":
    unittest.main()
