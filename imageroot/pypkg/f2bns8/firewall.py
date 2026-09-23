"""Atomic, permanent all-protocol filtering, independent of firewalld's table."""

import fcntl
import hashlib
import ipaddress
import subprocess
from .common import address, state_dir


def table_name(module):
    return "ns8_f2b_" + hashlib.sha256(module.encode()).hexdigest()[:12]


def rules(module, addresses, create):
    table = table_name(module)
    ips = sorted({address(ip) for ip in addresses})
    lines = []
    if create:
        lines += [f"add table inet {table}",
                  f"add set inet {table} banned4 {{ type ipv4_addr; }}",
                  f"add set inet {table} banned6 {{ type ipv6_addr; }}"]
        for hook in ("input", "output", "forward"):
            lines.append(f"add chain inet {table} {hook} {{ type filter hook {hook} priority -20; policy accept; }}")
            for version, family in ((4, "ip"), (6, "ip6")):
                for direction in (("saddr", "daddr") if hook == "forward" else (("saddr",) if hook == "input" else ("daddr",))):
                    lines.append(f"add rule inet {table} {hook} {family} {direction} @banned{version} counter drop")
    else:
        lines += [f"flush set inet {table} banned4", f"flush set inet {table} banned6"]
    for version in (4, 6):
        members = [ip for ip in ips if ipaddress.ip_address(ip).version == version]
        for start in range(0, len(members), 1000):
            lines.append(f"add element inet {table} banned{version} {{ " + ", ".join(members[start:start+1000]) + " }")
    return "\n".join(lines) + "\n"


def apply(module, addresses):
    with (state_dir() / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        exists = subprocess.run(["nft", "list", "table", "inet", table_name(module)], capture_output=True).returncode == 0
        subprocess.run(["nft", "-f", "-"], input=rules(module, addresses, not exists), text=True, capture_output=True, check=True, timeout=15)


def remove(module):
    subprocess.run(["nft", "delete", "table", "inet", table_name(module)], capture_output=True, check=False)
