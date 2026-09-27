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
    # Rootless container processes can journal under a subordinate UID, not
    # their module's login UID. Match the same ownership ranges as NS8 Alloy.
    subuids = {}
    try:
        for line in Path("/etc/subuid").read_text().splitlines():
            try:
                owner, start, count = line.split(":")
                start, count = int(start), int(count)
                if start > 0 and count > 0:
                    subuids.setdefault(owner, []).append((start, start + count))
            except ValueError:
                continue
    except FileNotFoundError:
        pass
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
            ranges = [(uid, uid + 1)]
            if uid:
                ranges += subuids.get(module, []) + subuids.get(str(uid), [])
            # Rootful modules all journal as UID 0. Podman's container ID is
            # the primary owner; an exact container name is a fallback for
            # older journal records without CONTAINER_ID_FULL.
            containers = {}
            if not uid:
                try:
                    rows = run_module(module, ["podman", "ps", "--no-trunc", "--format", "{{.ID}} {{.Names}}"])
                    containers = dict(line.split(None, 1) for line in rows.splitlines() if " " in line)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
            found.append({"module": module, "jail": kind, "uid": str(uid),
                "uid_ranges": ranges, "containers": containers, "environment": env})
    return found


def owns_record(source, record):
    try:
        uid = int(record.get("_UID", -1))
    except (ValueError, TypeError):
        return False
    if not any(start <= uid < end for start, end in source["uid_ranges"]):
        return False
    if source["uid"] != "0":
        return True
    containers = source.get("containers", {})
    container_id = record.get("CONTAINER_ID_FULL") or record.get("CONTAINER_ID")
    if container_id:
        return any(full_id.startswith(container_id) for full_id in containers)
    return record.get("CONTAINER_NAME") in containers.values()


def samba_logging(source):
    """Persist audit failures and apply the level live without restarting Samba."""
    module = source["module"]
    old = source["environment"].get("SAMBA_LOGLEVEL", "1 auth_audit:0 auth_json_audit:0")
    level = re.search(r"(?:^|\s)auth_json_audit:(\d+)(?:\s|$)", old)
    new = old if level and int(level[1]) >= 2 else re.sub(r"(?:^|\s)auth_json_audit:\S+", "", old) + " auth_json_audit:2"
    if new != old:
        path = state_dir() / "samba_loglevel.json"
        changes = read_json(path, {})
        if module in changes:
            if old != changes[module]["set"]:
                raise RuntimeError("Samba logging was changed externally; leaving it untouched")
        else:
            changes[module] = {"old": old, "set": new, "present": "SAMBA_LOGLEVEL" in source["environment"]}
            atomic_json(path, changes)
        run_module(module, ["python3", "-c", "import agent,json,sys; agent.set_env('SAMBA_LOGLEVEL',json.load(sys.stdin)); agent.dump_env()"], input=json.dumps(new))
    # The live debug command also covers an already running container with old env.
    run_module(module, ["podman", "exec", "samba-dc", "smbcontrol", "all", "debug", new])


def restore_samba_logging():
    path = state_dir() / "samba_loglevel.json"
    changes = read_json(path, {})
    if not changes:
        return
    sources = {source["module"]: source for source in discover()}
    for module, change in list(changes.items()):
        source = sources.get(module)
        if source and source["environment"].get("SAMBA_LOGLEVEL", "1 auth_audit:0 auth_json_audit:0") == change["set"]:
            if change.get("present", True):
                run_module(module, ["python3", "-c", "import agent,json,sys; agent.set_env('SAMBA_LOGLEVEL',json.load(sys.stdin)); agent.dump_env()"], input=json.dumps(change["old"]))
            else:
                run_module(module, ["python3", "-c", "import agent; agent.unset_env('SAMBA_LOGLEVEL'); agent.dump_env()"])
            run_module(module, ["podman", "exec", "samba-dc", "smbcontrol", "all", "debug", change["old"]])
        del changes[module]
        atomic_json(path, changes)


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
        seen = self.checkpoint.setdefault("file_seen", {})
        for key in self.checkpoint.get("files", {}):
            seen.setdefault(key, self.checkpoint.get("started", time.time()))
        self.sources = []
        self.files = []
        self.last_save = self.last_status = 0
        # Saved at once after a detection, so a restart cannot count the same
        # failure twice. Other progress is saved at most every 10 seconds.
        self.dirty = not (self.root / "collector.json").exists()
        self.detected = False
        self.ssh_sessions = {}
        (self.root / "logs").mkdir(exist_ok=True)

    def save(self, force=False):
        if self.dirty and (force or self.detected or time.monotonic() - self.last_save >= 10):
            atomic_json(self.root / "collector.json", self.checkpoint)
            self.dirty = self.detected = False
            self.last_save = time.monotonic()

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
        seen = self.checkpoint.setdefault("file_seen", {})
        for key in list(self.checkpoint.get("files", {})):
            if time.time() - seen.get(key, self.checkpoint.get("started", time.time())) > 86400:
                del self.checkpoint["files"][key]
                self.checkpoint.get("discarding", {}).pop(key, None)
                seen.pop(key, None)
                self.dirty = True

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
        os.chmod(path, 0o640)  # The isolated engine reads logs as the shared group.
        self.detected = True
        self.node.set("last_detection", {"jail": jail, "module": module, "time": now()})

    def journal(self, record):
        if record.get("__CURSOR") == self.checkpoint["cursor"]:
            return
        message = record.get("MESSAGE", "")
        if not isinstance(message, str):
            return
        when = int(record.get("__REALTIME_TIMESTAMP", "0")) / 1000000
        unit = record.get("_SYSTEMD_UNIT", "")
        if unit in ("sshd.service", "ssh.service") or re.fullmatch(r"sshd@[^/]+\.service", unit) or record.get("SYSLOG_IDENTIFIER") == "sshd":
            from .parsers import ssh_detail
            detail = ssh_detail(message)
            if detail:
                ip, primary = detail
                key = (record.get("_PID"), ip)
                if key[0]:
                    # OpenSSH can report an invalid user, a failed password and
                    # a connection close for the same session. Count the first
                    # auxiliary line only; primary attempts remain distinct.
                    previous = self.ssh_sessions.get(key, {"aux": False, "primary": False})
                    count = primary and not (previous["aux"] and not previous["primary"])
                    count = count or (not primary and not previous["aux"] and not previous["primary"])
                    self.ssh_sessions[key] = {"aux": previous["aux"] or not primary,
                                              "primary": previous["primary"] or primary, "time": when}
                    if len(self.ssh_sessions) > 4096:
                        self.ssh_sessions = {k: v for k, v in self.ssh_sessions.items() if when - v["time"] < 600}
                        if len(self.ssh_sessions) > 4096:
                            oldest = sorted(self.ssh_sessions, key=lambda k: self.ssh_sessions[k]["time"])
                            for stale in oldest[:len(self.ssh_sessions) - 4096]:
                                del self.ssh_sessions[stale]
                    if count:
                        self.emit("sshd", "host", message, when)
                else:
                    self.emit("sshd", "host", message, when)
        else:
            owners = [source for source in self.sources if source["jail"] != "organizr" and owns_record(source, record)]
            if len(owners) == 1:
                self.emit(owners[0]["jail"], owners[0]["module"], message, when)
        if record.get("__CURSOR"):
            self.checkpoint["cursor"] = record["__CURSOR"]
            self.checkpoint["since"] = when
            self.dirty = True

    def tail_files(self):
        for source, path in self.files:
            try:
                stat = path.stat()
                key = str(stat.st_dev) + ":" + str(stat.st_ino)
                seen = self.checkpoint.setdefault("file_seen", {})
                if time.time() - seen.get(key, 0) > 3600:
                    seen[key] = time.time()
                    self.dirty = True
                saved = self.checkpoint["files"].get(key, 0)
                discarding = self.checkpoint.setdefault("discarding", {})
                before = (self.checkpoint["files"].get(key), key in discarding)
                if saved > stat.st_size:
                    saved = 0
                    discarding.pop(key, None)
                with path.open("rb") as stream:
                    stream.seek(saved)
                    for _ in range(1000):
                        offset = stream.tell()
                        line = stream.readline(65537)
                        if not line:
                            break
                        # Advance past oversized records, including records that
                        # arrive over several reads. Otherwise one long line can
                        # permanently prevent later login failures being read.
                        if key in discarding or len(line) > 65536:
                            if line.endswith(b"\n"):
                                discarding.pop(key, None)
                            else:
                                discarding[key] = True
                            continue
                        if not line.endswith(b"\n"):
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
                if (self.checkpoint["files"][key], key in discarding) != before:
                    self.dirty = True
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
                self.save()
                if time.monotonic() - self.last_status >= 30:
                    self.node.set("collector_status", {"ok": True, "updated": now(), "error": ""})
                    self.last_status = time.monotonic()
                if time.monotonic() - refreshed > 60:
                    self.refresh()
                    refreshed = time.monotonic()
            if cursor:
                # A journal vacuum or reboot can invalidate a saved cursor.
                # Resume from its timestamp, not from historical login failures.
                self.checkpoint["cursor"] = ""
                self.dirty = True
            raise RuntimeError("Journal reader stopped; systemd will restart collection")
        finally:
            self.save(force=True)
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
