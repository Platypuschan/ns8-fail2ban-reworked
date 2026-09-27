#!/usr/bin/env python3
"""Machine-readable Fail2ban socket client inside the isolated container."""
import json
import sys
from fail2ban.client.csocket import CSocket

request = json.load(sys.stdin)
client = CSocket("/state/fail2ban.sock")
try:
    def send(command):
        response = client.send(command)
        if response[0] != 0:
            raise RuntimeError(str(response[1]))
        return response[1]
    print(json.dumps([send(item) for item in request["batch"]] if
        isinstance(request, dict) and "batch" in request else send(request), default=str))
finally:
    client.close()
