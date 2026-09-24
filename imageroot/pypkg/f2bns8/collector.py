"""Discover NS8 application instances and collect their authentication failures."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import select
import subprocess
import time
from zoneinfo import ZoneInfo
from .common import JAILS, atomic_json, config, now, read_json, state_dir
from .node import Node
from .parsers import parse


def run_module(module, args, **kwargs):
    return subprocess.run(["runagent", "-m", module] + args, text=True,
        capture_output=True, check=True, timeout=30, **kwargs).stdout


def discover():
    import agent
    found = []
    paths = list(Path("/home").glob("*/.config/state/environment"))
    paths += list(Path("/var/lib/nethserver").glob("*/state/environment"))
    for path in paths:
        env = agent.read_envfile(str(path))
        module = env.get("MODULE_ID", path.parts[-4] if ".config" in path.parts else path.parts[-3])
        if not re.fullmatch(r"[a-zA-Z0-9_-]+\d+", module):
            continue
        kind = next((j for j, key in (("gitea", "GITEA_IMAGE"), ("organizr", "ORGANIZR_IMAGE"),
                     ("samba", "SAMBA_IMAGE"), ("samba", "SAMBA_DC_IMAGE"), ("ns8", "TRAEFIK_IMAGE")) if key in env), None)
        if not kind:
            # Samba images can be named SAMBA_DC_IMAGE or SAMBA_IMAGE across releases.
            if any("SAMBA" in key and key.endswith("_IMAGE") for key in env):
                kind = "samba"
        if kind:
            try:
                uid = pwd.getpwnam(module).pw_uid
            except KeyError:
                uid = 0
            found.append({"module": module, "jail": kind, "uid": str(uid), "environment": env})
    return found


def samba_logging(source):
    """Persist audit failures and apply the level live without restarting Samba."""
    module = source["module"]
    old = source["environment"].get("SAMBA_LOGLEVEL", "1 auth_audit:0 auth_json_audit:0")
    level = re.search(r"(?:^|\s)auth_json_audit:(\d+)(?:\s|$)", old)
    new = old if level and int(level[1]) >= 2 else re.sub(r"(?:^|\s)auth_json_audit:\S+", "", old) + " auth_json_audit:2"
    if new != old:
        run_module(module, ["python3", "-c", "import agent,json,sys; agent.set_env('SAMBA_LOGLEVEL',json.load(sys.stdin)); agent.dump_env()"], input=json.dumps(new))
    # The live debug command also covers an already running container with old env.
    run_module(module, ["podman", "exec", "samba-dc", "smbcontrol", "all", "debug", new])


def log_files(source):
    values = json.loads(run_module(source["module"], ["podman", "volume", "inspect", "organizr-app"]))
    root = Path(values[0]["Mountpoint"])
    result = []
    for directory, children, files in os.walk(root):
        children[:] = [x for x in children if x not in ("vendor", "node_modules", ".git", "cache")]
        for name in files:
            if name.startswith("organizr") and name.endswith(".log"):
                path = Path(directory) / name
                if path.is_file() and not path.is_symlink():
                    result.append(path)
    return result


class Collector:
    def __init__(self):
        self.root = state_dir()
        self.node = Node(self.root / "node.sqlite3")
        self.checkpoint = read_json(self.root / "collector.json", {"cursor": "", "files": {}, "started": time.time(), "since": time.time()})
        self.sources = []
        self.files = []
        self.last_save = 0
        (self.root / "logs").mkdir(exist_ok=True)

    def refresh(self):
        self.sources = discover()
        self.files = []
        details = [{"jail": "sshd", "module": "host", "ready": True, "source": "journal", "error": ""}]
        for source in self.sources:
            detail = {k: source[k] for k in ("jail", "module")}
            detail.update(ready=True, source="journal", error="")
            try:
                if source["jail"] == "samba":
                    samba_logging(source)
                elif source["jail"] == "organizr":
                    paths = log_files(source)
                    self.files.extend((source, p) for p in paths)
                    detail["source"] = "JSON log files"
                    if not paths:
                        detail.update(ready=False, error="No Organizr authentication log yet; it is created by the first login event.")
            except Exception as error:
                detail.update(ready=False, error=str(error)[:300])
            details.append(detail)
        if not any(d["jail"] == "ns8" for d in details):
            details.append({"jail": "ns8", "module": "cluster-admin", "ready": False, "source": "Traefik access log", "error": "No local NS8 Traefik module discovered"})
        self.node.set("sources", details)

    def emit(self, jail, module, message, when):
        ip = parse(jail, message)
        if not ip or when < self.checkpoint.get("started", 0) or time.time() - when > 600 or when - time.time() > 60:
            return
        stamp = datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
        record = json.dumps({"module": module, "log": message}, ensure_ascii=True)
        path = self.root / "logs" / (jail + ".log")
        # Rotate by rename; Fail2ban's polling backend follows the replacement.
        if path.exists() and path.stat().st_size > 10 * 1024 * 1024:
            os.replace(path, path.with_suffix(".log.1"))
        with path.open("a") as stream:
            stream.write(stamp + " " + ip + " " + record + "\n")
        self.node.set("last_detection", {"jail": jail, "module": module, "time": now()})

    def journal(self, record):
        if record.get("__CURSOR") == self.checkpoint["cursor"]:
            return
        message = record.get("MESSAGE", "")
        if not isinstance(message, str):
            return
        when = int(record.get("__REALTIME_TIMESTAMP", "0")) / 1000000
        if record.get("_SYSTEMD_UNIT") in ("sshd.service", "ssh.service") or record.get("SYSLOG_IDENTIFIER") == "sshd":
            self.emit("sshd", "host", message, when)
        else:
            for source in self.sources:
                if source["jail"] == "organizr":
                    continue
                if record.get("_UID") == source["uid"] and (
                    source["uid"] != "0" or record.get("CONTAINER_NAME", "").startswith(source["module"])
                ):
                    self.emit(source["jail"], source["module"], message, when)
        if record.get("__CURSOR"):
            self.checkpoint["cursor"] = record["__CURSOR"]
            self.checkpoint["since"] = when

    def tail_files(self):
        for source, path in self.files:
            try:
                stat = path.stat()
                key = str(stat.st_dev) + ":" + str(stat.st_ino)
                saved = self.checkpoint["files"].get(key, 0)
                if saved > stat.st_size:
                    saved = 0
                with path.open("rb") as stream:
                    stream.seek(saved)
                    for _ in range(1000):
                        offset = stream.tell()
                        line = stream.readline(65537)
                        if not line or not line.endswith(b"\n"):
                            stream.seek(offset)
                            break
                        if len(line) <= 65536:
                            try:
                                message = line.decode("utf-8")
                                obj = json.loads(message)
                                dt = datetime.fromisoformat(obj["datetime"])
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=ZoneInfo(obj.get("timezone", "UTC")))
                                self.emit("organizr", source["module"], message.rstrip(), dt.timestamp())
                            except (ValueError, KeyError, UnicodeError):
                                pass
                    self.checkpoint["files"][key] = stream.tell()
            except FileNotFoundError:
                continue  # Rotation; rediscovery follows.

    def run(self):
        self.refresh()
        command = ["journalctl", "--follow", "--output=json", "--no-pager", "--all", "--lines=all"]
        cursor = self.checkpoint["cursor"]
        command += ["--after-cursor=" + cursor] if cursor else ["--since=@" + str(self.checkpoint.get("since", time.time()))]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        pending, refreshed = b"", time.monotonic()
        try:
            while process.poll() is None:
                if select.select([process.stdout], [], [], 0.5)[0]:
                    pending += os.read(process.stdout.fileno(), 65536)
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        try:
                            self.journal(json.loads(line))
                        except (ValueError, TypeError):
                            pass
                self.tail_files()
                atomic_json(self.root / "collector.json", self.checkpoint)
                self.node.set("collector_status", {"ok": True, "updated": now(), "error": ""})
                if time.monotonic() - refreshed > 60:
                    self.refresh()
                    refreshed = time.monotonic()
            if cursor:
                # A journal vacuum or reboot can invalidate a saved cursor.
                # Resume from its timestamp, not from historical login failures.
                self.checkpoint["cursor"] = ""
                atomic_json(self.root / "collector.json", self.checkpoint)
            raise RuntimeError("Journal reader stopped; systemd will restart collection")
        finally:
            process.terminate()
            process.wait(timeout=10)


def main():
    collector = Collector()
    try:
        collector.run()
    except Exception as error:
        collector.node.set("collector_status", {"ok": False, "error": str(error)[:500]})
        raise


if __name__ == "__main__":
    main()
