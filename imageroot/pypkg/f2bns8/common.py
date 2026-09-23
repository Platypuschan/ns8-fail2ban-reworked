"""Validation and durable local storage. No third-party dependencies."""

import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

JAILS = ("sshd", "ns8", "gitea", "organizr", "samba")


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
def database(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    os.chmod(path, 0o600)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("BEGIN IMMEDIATE")
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
    return sorted(result)


def allowed(ip, whitelist):
    item = ipaddress.ip_address(address(ip))
    return any(item in ipaddress.ip_network(n) for n in whitelist)


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
