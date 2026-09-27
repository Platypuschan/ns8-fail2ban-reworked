"""Private HTTP API, exposed only through NS8 Traefik."""

import hmac
import gzip
import ipaddress
import logging
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from urllib.request import Request, build_opener, HTTPRedirectHandler
import zlib
from .common import config, state_dir
from .registry import Registry


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(base, token, path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    req = Request(base.rstrip("/") + path, data=payload,
                  headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept-Encoding": "gzip"})
    with build_opener(NoRedirects).open(req, timeout=10) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("Coordinator response exceeds 16 MiB")
        if response.headers.get("Content-Encoding") == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = decoder.decompress(raw, 64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024 or not decoder.eof:
                raise ValueError("Coordinator decoded response exceeds 64 MiB")
        return json.loads(raw)


def endpoint(settings):
    if settings["mode"] == "coordinator":
        return "http://127.0.0.1:" + str(settings["port"])
    return settings["sync_url"]


def call(settings, path, data=None):
    return request(endpoint(settings), settings["sync_token"], path, data)


def make_server(registry, token, port=0):
    attempts = defaultdict(deque)
    attempts_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_one_request(self):
            self.connection.settimeout(10)
            super().handle_one_request()

        def respond(self, status, body):
            payload = json.dumps(body).encode()
            compressed = len(payload) > 2048 and "gzip" in self.headers.get("Accept-Encoding", "")
            if compressed:
                payload = gzip.compress(payload, compresslevel=3)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if compressed:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            # Valid peers must never be locked out by an attacker spoofing a
            # forwarded address. Only invalid credentials consume a rate slot.
            if hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()):
                return True
            forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
            try:
                remote = str(ipaddress.ip_address(forwarded)) if forwarded else self.client_address[0]
            except ValueError:
                remote = self.client_address[0]
            stamp = time.monotonic()
            with attempts_lock:
                if len(attempts) > 4096:
                    for ip in list(attempts):
                        if not attempts[ip] or stamp - attempts[ip][-1] > 60:
                            del attempts[ip]
                    while len(attempts) > 4096:
                        del attempts[next(iter(attempts))]
                recent = attempts[remote]
                while recent and stamp - recent[0] > 60:
                    recent.popleft()
                limited = len(recent) >= 10
                if not limited:
                    recent.append(stamp)
            if limited:
                self.respond(429, {"error": "Too many failed authentications"})
            else:
                logging.warning("Fail2ban coordinator rejected authorization from %s", remote)
                self.respond(401, {"error": "Authentication required"})
            return False

        def do_GET(self):
            if not self.authorized():
                return
            if self.path != "/v1/state":
                return self.respond(404, {"error": "Unknown endpoint"})
            self.respond(200, registry.snapshot())

        def do_POST(self):
            if not self.authorized():
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1048576 or self.headers.get("Transfer-Encoding"):
                    return self.respond(413, {"error": "Invalid request size"})
                data = json.loads(self.rfile.read(length))
                if self.path == "/v1/sync":
                    result = registry.sync(data["node"], data["name"], data["revision"], data.get("identity", ""),
                                           data["events"], data.get("generation"), data.get("protected"), data.get("protocol"))
                elif self.path == "/v1/unban":
                    result = registry.unban(data["ips"])
                elif self.path == "/v1/whitelist":
                    result = registry.set_whitelist(data["whitelist"], data["revision"])
                else:
                    return self.respond(404, {"error": "Unknown endpoint"})
                self.respond(200, result)
            except (ValueError, TypeError, KeyError) as error:
                self.respond(409, {"error": str(error)})
            except Exception:
                self.respond(500, {"error": "Coordinator operation failed"})

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    settings = config()
    if settings.get("mode") != "coordinator":
        return
    make_server(Registry(state_dir() / "coordinator.sqlite3"), settings["sync_token"], settings["port"]).serve_forever()


if __name__ == "__main__":
    main()
