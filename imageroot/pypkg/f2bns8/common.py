"""Validation and durable local storage. No third-party dependencies."""

import contextlib
import bisect
import functools
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

JAILS = ("sshd", "ns8", "gitea", "organizr", "samba")
LOOPBACKS = ("127.0.0.0/8", "::1/128")
# Every network becomes a Fail2ban ignoreip entry in each jail, so bound the
# expanded list, not just the number of lines a user enters.
MAX_NETWORKS = 4096
_prepared = {}
_prepare_lock = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def state_dir():
    return Path(os.environ.get("F2B_STATE_DIR", os.environ.get("AGENT_STATE_DIR", "/state")))


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextlib.contextmanager
def database(path, readonly=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    db.row_factory = sqlite3.Row
    identity = (path.stat().st_dev, path.stat().st_ino)
    with _prepare_lock:
        if _prepared.get(str(path)) != identity:
            os.chmod(path, 0o600)
            db.execute("PRAGMA journal_mode=WAL")
            _prepared[str(path)] = identity
    if readonly:
        db.execute("PRAGMA query_only=ON")
    else:
        # synchronous is connection-local; journal_mode and chmod are not.
        db.execute("PRAGMA synchronous=FULL")
    # WAL readers see a consistent snapshot without blocking writers.
    db.execute("BEGIN" if readonly else "BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def address(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Invalid IP address")
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast:
        raise ValueError("A ban requires a unicast IP address")
    return str(ip)


def networks(values):
    if not isinstance(values, list):
        raise ValueError("Whitelist must be a list of addresses or ranges")
    if len(values) > MAX_NETWORKS:
        raise ValueError(f"Whitelist has more than {MAX_NETWORKS} entries")
    result = set()
    for value in values:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("Invalid whitelist entry")
        value = value.strip()
        if "-" in value:
            first, last = (ipaddress.ip_address(x.strip()) for x in value.split("-", 1))
            result.update(str(n) for n in ipaddress.summarize_address_range(first, last))
        else:
            result.add(str(ipaddress.ip_network(value, strict=False)))
    canonical = set()
    for value in result:
        net = ipaddress.ip_network(value)
        if isinstance(net, ipaddress.IPv6Network) and net.prefixlen >= 96 and net.network_address.ipv4_mapped:
            net = ipaddress.ip_network((net.network_address.ipv4_mapped, net.prefixlen - 96))
        canonical.add(str(net))
    if len(canonical) > MAX_NETWORKS:
        raise ValueError(f"Whitelist expands to {len(canonical)} networks; the limit is {MAX_NETWORKS}. "
                         "Use CIDR notation or fewer ranges.")
    return sorted(canonical)


def shared_whitelist(values):
    # A host-wide ban on loopback would break the coordinator and other NS8
    # services. These two local-only networks are therefore invariant.
    return networks(sorted(set(networks(values)).union(LOOPBACKS)))


@functools.lru_cache(maxsize=16)
def _parsed(whitelist):
    families = ([], [])
    for value in whitelist:
        network = ipaddress.ip_network(value)
        families[0 if network.version == 4 else 1].append(
            (int(network.network_address), int(network.broadcast_address)))
    indexes = []
    for intervals in families:
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        indexes.append((tuple(start for start, _ in merged), tuple(end for _, end in merged)))
    return tuple(indexes)


def allowed(ip, whitelist):
    item = ipaddress.ip_address(address(ip))
    starts, ends = _parsed(tuple(whitelist))[0 if item.version == 4 else 1]
    offset = bisect.bisect_right(starts, int(item)) - 1
    return offset >= 0 and int(item) <= ends[offset]


@functools.lru_cache(maxsize=2)
def _local_protection(bucket):
    """Protect interface IPs, directly routed VPN subnets and the sync peer."""
    result = set(LOOPBACKS)
    vpn = set()
    try:
        interfaces = json.loads(subprocess.run(["ip", "-j", "address", "show"], capture_output=True,
                                               text=True, check=True, timeout=5).stdout)
        for interface in interfaces:
            name = interface.get("ifname", "")
            if name.startswith(("wg", "tun", "tailscale", "nebula", "zt")):
                vpn.add(name)
            for info in interface.get("addr_info", []):
                ip = info.get("local", "")
                try:
                    result.add(str(ipaddress.ip_network(address(ip) + ("/32" if ":" not in ip else "/128"))))
                    if name in vpn:
                        result.add(str(ipaddress.ip_network(f"{ip}/{info['prefixlen']}", strict=False)))
                except (ValueError, KeyError):
                    pass
        if vpn:
            routes = json.loads(subprocess.run(["ip", "-j", "route", "show", "table", "all"],
                                              capture_output=True, text=True, check=True, timeout=5).stdout)
            for route in routes:
                if route.get("dev") not in vpn or route.get("dst") in (None, "default"):
                    continue
                try:
                    net = ipaddress.ip_network(route["dst"], strict=False)
                    if net.prefixlen >= (16 if net.version == 4 else 48):
                        result.add(str(net))
                except ValueError:
                    pass
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
        pass
    settings = config()
    try:
        host = urlsplit(settings.get("sync_url") or settings.get("public_url", "")).hostname
        if host:
            for entry in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                ip = address(entry[4][0])
                result.add(ip + ("/32" if ":" not in ip else "/128"))
    except (OSError, ValueError):
        pass
    return tuple(sorted(result))


def local_protection():
    return _local_protection(int(time.monotonic() // 60))


def url(value, https_only=True):
    parsed = urlsplit(value.strip())
    schemes = ("https",) if https_only else ("http", "https")
    if (parsed.scheme not in schemes or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Enter an HTTPS URL without credentials, query or fragment")
    parsed.port  # validate port syntax
    return value.strip().rstrip("/")


def public_host(value):
    value = url(value)
    parsed = urlsplit(value)
    if parsed.port not in (None, 443) or parsed.path not in ("", "/"):
        raise ValueError("Coordinator URL must be https://hostname without a port or path")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if len(host) > 253 or "." not in host or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise ValueError("Coordinator needs a fully qualified DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("Use a DNS hostname for the NS8 certificate")


def config():
    return read_json(state_dir() / "config.json", {})


def safe_text(value, limit=16384):
    return "".join(c for c in str(value) if c in "\n\t" or ord(c) >= 32)[:limit]
