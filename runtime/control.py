#!/usr/bin/env python3
"""Machine-readable Fail2ban socket client inside the isolated container."""
import json
import ipaddress
import os
from pathlib import Path
import sys
from fail2ban.client.csocket import CSocket

request = json.load(sys.stdin)
client = CSocket(str(Path(os.environ.get("F2B_STATE_DIR", "/state")) / "engine/fail2ban.sock"))
try:
    def send(command):
        response = client.send(command)
        if response[0] != 0:
            raise RuntimeError(str(response[1]))
        return response[1]

    if isinstance(request, dict) and "reconcile" in request:
        desired = request["reconcile"]
        wanted = set(desired["bans"])
        whitelist = set(desired["whitelist"])
        status = send(["status"])
        jails = next((item[1] for item in status if "Jail list" in item[0]), "")
        changes = 0
        for jail in (j.strip() for j in jails.split(",") if j.strip()):
            for ip in send(["get", jail, "banip"]):
                if ip not in wanted:
                    send(["set", jail, "unbanip", ip])
                    changes += 1
            current = {str(ipaddress.ip_network(value, strict=False)) for value in send(["get", jail, "ignoreip"])}
            for ip in current - whitelist:
                send(["set", jail, "delignoreip", ip])
                changes += 1
            for ip in whitelist - current:
                send(["set", jail, "addignoreip", ip])
                changes += 1
        print(json.dumps({"changes": changes}))
    else:
        print(json.dumps(send(request), default=str))
finally:
    client.close()
