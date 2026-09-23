"""Fail2ban calls this Python action directly. Log data is never a shell command."""
import json
from fail2ban.server.action import ActionBase
from f2bns8.common import config, state_dir
from f2bns8.node import Node


class Action(ActionBase):
    norestored = True

    def ban(self, info):
        if info.get("restored", 0):
            return
        settings = config()
        lines, modules = [], set()
        for line in str(info.get("matches", "")).splitlines():
            try:
                record = json.loads(line[line.index("{"):])
                lines.append(record["log"])
                modules.add(record["module"])
            except (ValueError, KeyError, TypeError):
                lines.append(line)
        Node(state_dir() / "node.sqlite3").ban(
            str(info["ip"]), self._jail.name, ", ".join(sorted(modules)),
            settings.get("node_name", ""), "\n".join(lines),
            notify=settings.get("notifications", {}).get("enabled", False))

    def unban(self, info):
        # Jail shutdown/reload is not a user request to remove a permanent ban.
        pass
