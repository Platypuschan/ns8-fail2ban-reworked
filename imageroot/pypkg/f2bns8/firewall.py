"""Atomic, permanent all-protocol filtering, independent of firewalld's table."""

import fcntl
import hashlib
import ipaddress
import os
import re
import subprocess
from .common import address, state_dir


def table_name(module):
    return "ns8_f2b_" + hashlib.sha256(module.encode()).hexdigest()[:12]


def rules(module, addresses, create, replace=False):
    table = table_name(module)
    ips = sorted({address(ip) for ip in addresses})
    lines = []
    if create:
        if replace:
            lines.append(f"delete table inet {table}")
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


def intact(module, listing):
    """Check the hooks and every drop rule, not just the table's existence."""
    table = re.escape(table_name(module))
    if not re.search(r"\btable inet " + table + r"\b", listing):
        return False
    for version in (4, 6):
        if not re.search(r"\bset banned" + str(version) + r"\s*\{", listing):
            return False
    for hook in ("input", "output", "forward"):
        chain = re.search(r"\bchain " + hook + r"\s*\{([^{}]*)\}", listing, re.S)
        if not chain or not re.search(r"\bhook " + hook + r" priority (?:-20|filter - 20); policy accept;", chain[1]):
            return False
        expected = ("saddr", "daddr") if hook == "forward" else (("saddr",) if hook == "input" else ("daddr",))
        for family, version in (("ip", 4), ("ip6", 6)):
            for direction in expected:
                if not re.search(r"\b" + family + " " + direction + r" @banned" + str(version) + r"\b[^\n]*\bcounter\b[^\n]*\bdrop\b", chain[1]):
                    return False
    return True


def apply(module, addresses):
    with (state_dir() / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = subprocess.run(["nft", "list", "table", "inet", table_name(module)],
                                 capture_output=True, text=True, timeout=15)
        exists = current.returncode == 0
        healthy = exists and intact(module, current.stdout)
        subprocess.run(["nft", "-f", "-"], input=rules(module, addresses, not healthy, replace=exists and not healthy),
                       text=True, capture_output=True, check=True, timeout=15)


def remove(module):
    subprocess.run(["nft", "delete", "table", "inet", table_name(module)], capture_output=True, check=False)


if __name__ == "__main__":
    from .node import Node
    apply(os.environ["MODULE_ID"], [ban["ip"] for ban in Node(state_dir() / "node.sqlite3").bans()])
