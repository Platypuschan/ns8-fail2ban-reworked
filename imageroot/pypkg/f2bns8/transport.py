"""Private HTTP API, exposed only through NS8 Traefik."""

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.request import Request, build_opener, HTTPRedirectHandler
from .common import config, state_dir
from .registry import Registry


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(base, token, path, data=None):
    payload = None if data is None else json.dumps(data).encode()
    req = Request(base.rstrip("/") + path, data=payload,
                  headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with build_opener(NoRedirects).open(req, timeout=10) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("Coordinator response exceeds 16 MiB")
        return json.loads(raw)


def endpoint(settings):
    if settings["mode"] == "coordinator":
        return "http://127.0.0.1:" + str(settings["port"])
    return settings["sync_url"]


def call(settings, path, data=None):
    return request(endpoint(settings), settings["sync_token"], path, data)


def make_server(registry, token, port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_one_request(self):
            self.connection.settimeout(10)
            super().handle_one_request()

        def respond(self, status, body):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            return hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + token).encode())

        def do_GET(self):
            if not self.authorized():
                return self.respond(401, {"error": "Authentication required"})
            if self.path != "/v1/state":
                return self.respond(404, {"error": "Unknown endpoint"})
            self.respond(200, registry.snapshot())

        def do_POST(self):
            if not self.authorized():
                return self.respond(401, {"error": "Authentication required"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1048576 or self.headers.get("Transfer-Encoding"):
                    return self.respond(413, {"error": "Invalid request size"})
                data = json.loads(self.rfile.read(length))
                if self.path == "/v1/sync":
                    result = registry.sync(data["node"], data["name"], data["revision"], data.get("identity", ""), data["events"])
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
