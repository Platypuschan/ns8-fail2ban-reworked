"""Fail2ban calls this Python action directly. Log data is never a shell command."""
import json
from fail2ban.server.action import ActionBase
from f2bns8.queue import enqueue


class Action(ActionBase):
    norestored = True

    def ban(self, info):
        if info.get("restored", 0):
            return
        lines, modules = [], set()
        for line in str(info.get("matches", "")).splitlines():
            try:
                record = json.loads(line[line.index("{"):])
                lines.append(record["log"])
                modules.add(record["module"])
            except (ValueError, KeyError, TypeError):
                lines.append(line)
        enqueue({"ip": str(info["ip"]), "jail": self._jail.name,
                 "module": ", ".join(sorted(modules)), "matches": "\n".join(lines)})

    def unban(self, info):
        # Jail shutdown/reload is not a user request to remove a permanent ban.
        pass
