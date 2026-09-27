"""Validation and durable local storage. No third-party dependencies."""

import contextlib
from bisect import bisect_right
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
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

JAILS = ("sshd", "ns8", "gitea", "organizr", "samba")
LOOPBACKS = ("127.0.0.0/8", "::1/128")


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
def database(path, write=True):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    new = not Path(path).exists()
    db = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    if new:
        os.chmod(path, 0o600)
    db.row_factory = sqlite3.Row
    if new:
        db.execute("PRAGMA journal_mode=WAL")
    db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
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
    if not isinstance(values, list) or len(values) > 4096:
        raise ValueError("Whitelist must be a list of addresses or ranges")
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
    return sorted(canonical)


@functools.lru_cache(maxsize=32)
def _parsed_networks(whitelist):
    result = []
    for version in (4, 6):
        spans = sorted((int(net.network_address), int(net.broadcast_address))
            for value in whitelist if (net := ipaddress.ip_network(value)).version == version)
        merged = []
        for start, end in spans:
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        result.append((tuple(start for start, _ in merged), tuple(end for _, end in merged)))
    return tuple(result)


def allowed(ip, whitelist):
    item = ipaddress.ip_address(address(ip))
    starts, ends = _parsed_networks(tuple(whitelist))[0 if item.version == 4 else 1]
    pos = bisect_right(starts, int(item)) - 1
    return pos >= 0 and int(item) <= ends[pos]


@functools.lru_cache(maxsize=2)
def _local_networks(interval):
    try:
        result = subprocess.run(["ip", "-json", "address", "show"], text=True,
            capture_output=True, check=True, timeout=5)
        interfaces = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        interfaces = []
        try:
            interfaces = [{"addr_info": [{"local": item[4][0]}
                for item in socket.getaddrinfo(socket.gethostname(), None)]}]
        except OSError:
            pass
    addresses = []
    for interface in interfaces:
        for item in interface.get("addr_info", []):
            try:
                if item.get("temporary") or "temporary" in item.get("flags", []):
                    continue
                ip = ipaddress.ip_address(item["local"].split("%", 1)[0])
                if not ip.is_loopback and not ip.is_unspecified:
                    addresses.append(str(ipaddress.ip_network((ip, ip.max_prefixlen))))
            except (KeyError, ValueError):
                continue
    return tuple(sorted(set(addresses)))


def local_networks():
    return list(_local_networks(int(time.monotonic() // 60)))


def protected_networks():
    # Exact interface addresses are protected on every node. Additional VPN
    # ranges are explicitly configured by the administrator for this cluster.
    return sorted(set(local_networks() + config().get("protected_networks", [])))


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
