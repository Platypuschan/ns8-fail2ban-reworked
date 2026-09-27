"""One-way, durable handoff from the untrusted log engine to the host worker."""

import json
import os
from pathlib import Path
import uuid
from .common import JAILS, address, atomic_json, state_dir


def enqueue(event):
    atomic_json(state_dir() / "engine/queue" / (str(uuid.uuid4()) + ".json"), event)


def drain(node, settings, limit=100):
    directory = Path(node.path).parent / "engine/queue"
    for path in sorted(directory.glob("*.json"))[:limit]:
        if path.is_symlink():
            continue
        try:
            uuid.UUID(path.stem)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError("Engine event too large")
            event = json.loads(raw)
            if event["jail"] not in JAILS or not all(isinstance(event[k], str) for k in ("ip", "jail", "module", "matches")):
                raise ValueError("Invalid engine event")
            event = (address(event["ip"]), event["jail"], event["module"], event["matches"])
        except (ValueError, KeyError, TypeError, OSError):
            # Malformed engine output cannot stop firewall reconciliation.
            path.unlink(missing_ok=True)
            continue
        node.ban(*event[:3], settings.get("node_name", ""), event[3],
                 notify=settings.get("notifications", {}).get("enabled", False))
        path.unlink(missing_ok=True)
