from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.path == "/test"
        message = self.rfile.read(int(self.headers["Content-Length"])).decode()
        with Path("/tmp/ns8-notifications.jsonl").open("a") as stream:
            stream.write(json.dumps(message) + "\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')


HTTPServer(("127.0.0.1", 18888), Handler).serve_forever()
