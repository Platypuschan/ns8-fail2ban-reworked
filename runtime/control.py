#!/usr/bin/env python3
"""Machine-readable Fail2ban socket client inside the isolated container."""
import json
import sys
from fail2ban.client.csocket import CSocket

request = json.load(sys.stdin)
client = CSocket("/state/fail2ban.sock")
try:
    response = client.send(request)
    if response[0] != 0:
        raise RuntimeError(str(response[1]))
    print(json.dumps(response[1], default=str))
finally:
    client.close()
