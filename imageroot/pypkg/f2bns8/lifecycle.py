"""NS8 rootful service lifecycle. No firewall or database port is published."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import uuid
from .common import JAILS, atomic_json, config, public_host, state_dir

PARTS = ("coordinator", "worker", "collector", "notify", "engine", "firewall")


def systemctl(*args, check=True):
    return subprocess.run(["systemctl"] + list(args), check=check, capture_output=True, text=True, timeout=90)


def route(settings, delete=False):
    import agent
    import agent.tasks
    traefik = agent.resolve_agent_id("traefik@node")
    if not traefik:
        raise RuntimeError("NS8 Traefik module is required on this node")
    data = {"instance": os.environ["MODULE_ID"]}
    if not delete:
        data.update(url="http://127.0.0.1:" + str(settings["port"]),
            host=public_host(settings["public_url"]), http2https=True, lets_encrypt=True)
    result = agent.tasks.run(agent_id=traefik, action="delete-route" if delete else "set-route", data=data)
    if result["exit_code"]:
        raise RuntimeError("NS8 reverse proxy configuration failed")


def install():
    module = os.environ["MODULE_ID"]
    root = state_dir()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    logs = root / "logs"
    logs.mkdir(exist_ok=True)
    os.chown(logs, 0, 65532)
    os.chmod(logs, 0o2750)  # New log files inherit the engine's read-only group.
    for jail in JAILS:
        path = logs / (jail + ".log")
        path.touch(exist_ok=True)
        os.chown(path, 0, 65532)
        os.chmod(path, 0o640)
    engine = root / "engine"
    (engine / "queue").mkdir(parents=True, exist_ok=True)
    for path in (engine, engine / "queue"):
        os.chown(path, 65532, 65532)
        os.chmod(path, 0o700)
    old_db = root / "fail2ban.sqlite3"
    new_db = engine / old_db.name
    if old_db.exists() and not new_db.exists():
        # Stop the previous engine before copying the on-disk SQLite database.
        systemctl("stop", module + "-engine.service", check=False)
        with sqlite3.connect(str(old_db)) as source, sqlite3.connect(str(new_db)) as target:
            source.backup(target)
        os.chown(new_db, 65532, 65532)
        os.chmod(new_db, 0o600)
    for part in PARTS:
        name = module + "-" + part + ".service"
        start = "/usr/local/bin/runagent -m " + module + " python3 -m f2bns8." + ("transport" if part == "coordinator" else part)
        extra = ""
        if part == "engine":
            image = os.environ.get("FAIL2BAN_ENGINE_IMAGE")
            if not image:
                raise RuntimeError("FAIL2BAN_ENGINE_IMAGE is missing from the NS8 image environment")
            start = ("/usr/bin/podman run --rm --replace --name " + module + "-engine"
                + " --network=none --cap-drop=all --security-opt=no-new-privileges --read-only --user=65532:65532"
                + " --tmpfs=/run:rw,nosuid,nodev,mode=1777"
                + " --volume=" + str(logs) + ":/state/logs:ro,z"
                + " --volume=" + str(engine) + ":/state/engine:rw,z"
                + " --env=F2B_STATE_DIR=/state --log-driver=journald " + image)
            extra = "ExecStop=/usr/bin/podman stop --ignore -t 15 " + module + "-engine\n"
        unit = ("[Unit]\nDescription=NS8 Fail2ban " + part + " (" + module + ")\n"
            "After=network-online.target\nWants=network-online.target\n"
            "StartLimitIntervalSec=0\n\n[Service]\nType=simple\nUMask=0077\n"
            "Restart=always\nRestartSec=3\nTimeoutStopSec=45\n"
            "ExecStart=" + start + "\n" + extra + "\n[Install]\nWantedBy=multi-user.target\n")
        if part == "firewall":
            unit = ("[Unit]\nDescription=Restore NS8 Fail2ban bans before networking\n"
                "DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n"
                "\n[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\nExecStart=" + start
                + "\n\n[Install]\nWantedBy=multi-user.target\n")
        Path("/etc/systemd/system", name).write_text(unit)
    systemctl("daemon-reload")


def start(settings):
    module = os.environ["MODULE_ID"]
    install()
    systemctl("enable", module + "-firewall.service")
    systemctl("restart", module + "-firewall.service")
    if settings["mode"] == "coordinator":
        systemctl("enable", module + "-coordinator.service")
        systemctl("restart", module + "-coordinator.service")
    else:
        systemctl("disable", "--now", module + "-coordinator.service", check=False)
    for part in ("engine", "worker", "collector", "notify"):
        systemctl("enable", module + "-" + part + ".service")
        systemctl("restart", module + "-" + part + ".service")


def destroy():
    from .firewall import remove
    module = os.environ["MODULE_ID"]
    for part in PARTS:
        name = module + "-" + part + ".service"
        systemctl("disable", "--now", name, check=False)
        Path("/etc/systemd/system", name).unlink(missing_ok=True)
    systemctl("daemon-reload")
    # Nothing manages the table once the services are gone, so never let a
    # reverse proxy failure leave its bans on the host.
    try:
        if config().get("mode") == "coordinator":
            route(config(), delete=True)
    finally:
        try:
            from .collector import restore_samba_logging
            restore_samba_logging()
        finally:
            remove(module)


def backup():
    root = state_dir()
    target = root / "backup"
    target.mkdir(exist_ok=True)
    for name in ("node", "coordinator", "fail2ban"):
        if name == "coordinator" and config().get("mode") != "coordinator":
            (target / "coordinator.sqlite3").unlink(missing_ok=True)
            continue
        path = (root / "engine" if name == "fail2ban" else root) / (name + ".sqlite3")
        if not path.exists():
            continue
        temp = target / (name + ".tmp")
        temp.unlink(missing_ok=True)
        with sqlite3.connect(str(path)) as source, sqlite3.connect(str(temp)) as destination:
            source.backup(destination)
        os.chmod(temp, 0o600)
        os.replace(temp, target / path.name)


def restore(clone=False):
    root = state_dir()
    (root / "engine").mkdir(exist_ok=True)
    for path in (root / "backup").glob("*.sqlite3"):
        if clone and path.name == "coordinator.sqlite3":
            continue
        destination = (root / "engine" if path.name == "fail2ban.sqlite3" else root) / path.name
        for suffix in ("", "-wal", "-shm"):
            Path(str(destination) + suffix).unlink(missing_ok=True)
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)
        if path.name == "fail2ban.sqlite3":
            os.chown(destination, 65532, 65532)
    if not clone and (root / "coordinator.sqlite3").exists():
        # Peers may already have newer revisions than this backup.
        from .registry import Registry
        Registry(root / "coordinator.sqlite3").new_generation()
    settings = config()
    if not settings:
        return
    settings["port"] = int(os.environ["TCP_PORT"])
    if clone:
        # A second authority with copied state would fork the common ban list.
        # Clones enroll as peers of the original coordinator instead.
        settings["node_id"] = str(uuid.uuid4())
        if settings["mode"] == "coordinator":
            settings.update(mode="peer", sync_url=settings["public_url"])
        for suffix in ("", "-wal", "-shm"):
            (root / ("coordinator.sqlite3" + suffix)).unlink(missing_ok=True)
        (root / "backup/coordinator.sqlite3").unlink(missing_ok=True)
        from .common import database
        with database(root / "node.sqlite3") as db:
            db.execute("DELETE FROM notifications")
    import socket
    settings["node_name"] = socket.getfqdn() + " / " + os.environ["MODULE_ID"]
    atomic_json(root / "config.json", settings)
    if settings["mode"] == "coordinator":
        route(settings)
    start(settings)
