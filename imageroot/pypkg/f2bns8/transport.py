"""Private HTTP API, exposed only through NS8 Traefik."""

import hmac
import base64
import hashlib
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import tempfile
import threading
import time
from collections import deque
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from .common import config, state_dir
from .registry import Registry


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(base, token, path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    req = Request(base.rstrip("/") + path, data=payload,
                  headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                           "X-F2B-Paging": "1"})
    with build_opener(NoRedirects).open(req, timeout=10) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("Coordinator response exceeds 16 MiB")
        result = json.loads(raw)
    if result.get("paged"):
        cursor, size = result["cursor"], result["size"]
        if not isinstance(size, int) or size < 0 or size > 1024 * 1024 * 1024:
            raise ValueError("Invalid coordinator snapshot size")
        chunks = []
        for offset in range(0, size, 512 * 1024):
            page = request(base, token, "/v1/page?cursor=" + cursor + "&offset=" + str(offset))
            if page["offset"] != offset:
                raise ValueError("Coordinator snapshot page is out of order")
            chunks.append(base64.b64decode(page["chunk"], validate=True))
        complete = b"".join(chunks)
        if len(complete) != size or hashlib.sha256(complete).hexdigest() != result["sha256"]:
            raise ValueError("Coordinator snapshot failed integrity check")
        return json.loads(complete)
    return result


def endpoint(settings):
    if settings["mode"] == "coordinator":
        return "http://127.0.0.1:" + str(settings["port"])
    return settings["sync_url"]


def call(settings, path, data=None):
    return request(endpoint(settings), settings["sync_token"], path, data)


def make_server(registry, token, port=0):
    failures = deque()
    failure_lock = threading.Lock()
    logger = logging.getLogger(__name__)
    pages = {}
    pages_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_one_request(self):
            self.connection.settimeout(10)
            super().handle_one_request()

        def respond(self, status, body):
            payload = json.dumps(body).encode()
            if self.headers.get("X-F2B-Paging") == "1" and len(payload) > 2 * 1024 * 1024:
                cursor = secrets.token_urlsafe(24)
                with pages_lock:
                    for key, (stream, seen, _) in list(pages.items()):
                        if seen < time.monotonic() - 120:
                            stream.close()
                            del pages[key]
                    if len(pages) >= 4:
                        oldest = min(pages, key=lambda key: pages[key][1])
                        pages.pop(oldest)[0].close()
                    stream = tempfile.TemporaryFile()
                    stream.write(payload)
                    pages[cursor] = (stream, time.monotonic(), len(payload))
                payload = json.dumps({"paged": True, "cursor": cursor, "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest()}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            # A correct token always works, even while invalid guesses are
            # throttled, so noisy clients cannot stop healthy peers syncing.
            if hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode()):
                return True
            with failure_lock:
                current = time.monotonic()
                while failures and failures[0] < current - 60:
                    failures.popleft()
                failures.append(current)
                count = len(failures)
            if count == 1 or count % 20 == 0:
                logger.warning("Coordinator authentication failures in the last minute: %d", count)
            if count > 20:
                self.send_response(429)
                self.send_header("Retry-After", "60")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.respond(401, {"error": "Authentication required"})
            return False

        def do_GET(self):
            if not self.authorized():
                return
            parsed = urlsplit(self.path)
            if parsed.path == "/v1/page":
                params = parse_qs(parsed.query)
                try:
                    cursor = params["cursor"][0]
                    offset = int(params["offset"][0])
                    if offset < 0 or offset % (512 * 1024):
                        raise ValueError()
                except (KeyError, IndexError, ValueError):
                    return self.respond(400, {"error": "Invalid page cursor"})
                with pages_lock:
                    entry = pages.get(cursor)
                    if not entry or offset >= entry[2]:
                        return self.respond(410, {"error": "Snapshot expired"})
                    stream, _, length = entry
                    stream.seek(offset)
                    chunk = stream.read(min(512 * 1024, length - offset))
                    pages[cursor] = (stream, time.monotonic(), length)
                return self.respond(200, {"offset": offset, "chunk": base64.b64encode(chunk).decode()})
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
                    result = registry.sync(data["node"], data["name"], data["revision"], data.get("identity", ""), data["events"], data.get("protected", []), data.get("acks", []), data.get("delta_supported", False))
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
