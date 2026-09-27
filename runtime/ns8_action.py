"""Fail2ban calls this Python action directly. Log data is never a shell command."""
import json
import uuid
from fail2ban.server.action import ActionBase
from f2bns8.common import atomic_json, read_json, state_dir


class Action(ActionBase):
    norestored = True

    def ban(self, info):
        if info.get("restored", 0):
            return
        settings = read_json(state_dir() / "meta.json", {})
        lines, modules = [], set()
        for line in str(info.get("matches", "")).splitlines():
            try:
                record = json.loads(line[line.index("{"):])
                lines.append(record["log"])
                modules.add(record["module"])
            except (ValueError, KeyError, TypeError):
                lines.append(line)
        atomic_json(state_dir() / "outbox" / (str(uuid.uuid4()) + ".json"), {
            "ip": str(info["ip"]), "jail": self._jail.name,
            "module": ", ".join(sorted(modules)), "node": settings.get("node_name", ""),
            "matches": "\n".join(lines), "notify": settings.get("notify", False)})

    def unban(self, info):
        # Jail shutdown/reload is not a user request to remove a permanent ban.
        pass
