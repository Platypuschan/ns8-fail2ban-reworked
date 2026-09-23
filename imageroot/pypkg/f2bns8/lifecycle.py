"""NS8 rootful service lifecycle. No firewall or database port is published."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import uuid
from .common import atomic_json, config, public_host, state_dir

PARTS = ("coordinator", "worker", "collector", "notify", "engine")


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
    for part in PARTS:
        name = module + "-" + part + ".service"
        start = "/usr/local/bin/runagent -m " + module + " python3 -m f2bns8." + ("transport" if part == "coordinator" else part)
        extra = ""
        if part == "engine":
            image = os.environ.get("FAIL2BAN_ENGINE_IMAGE")
            if not image:
                raise RuntimeError("FAIL2BAN_ENGINE_IMAGE is missing from the NS8 image environment")
            start = ("/usr/bin/podman run --rm --replace --name " + module + "-engine"
                + " --network=none --cap-drop=all --security-opt=no-new-privileges --read-only"
                + " --tmpfs=/run:rw,nosuid,nodev --volume=" + str(root) + ":/state:z"
                + " --env=F2B_STATE_DIR=/state --log-driver=journald " + image)
            extra = "ExecStop=/usr/bin/podman stop --ignore -t 15 " + module + "-engine\n"
        unit = ("[Unit]\nDescription=NS8 Fail2ban " + part + " (" + module + ")\n"
            "After=network-online.target\nWants=network-online.target\n"
            "StartLimitIntervalSec=0\n\n[Service]\nType=simple\nUMask=0077\n"
            "Restart=always\nRestartSec=3\nTimeoutStopSec=45\n"
            "ExecStart=" + start + "\n" + extra + "\n[Install]\nWantedBy=multi-user.target\n")
        Path("/etc/systemd/system", name).write_text(unit)
    systemctl("daemon-reload")


def start(settings):
    module = os.environ["MODULE_ID"]
    install()
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
    if config().get("mode") == "coordinator":
        route(config(), delete=True)
    remove(module)


def backup():
    root = state_dir()
    target = root / "backup"
    target.mkdir(exist_ok=True)
    for name in ("node", "coordinator", "fail2ban"):
        path = root / (name + ".sqlite3")
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
    for path in (root / "backup").glob("*.sqlite3"):
        for suffix in ("", "-wal", "-shm"):
            (root / (path.name + suffix)).unlink(missing_ok=True)
        shutil.copyfile(path, root / path.name)
        os.chmod(root / path.name, 0o600)
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
        from .common import database
        with database(root / "node.sqlite3") as db:
            db.execute("DELETE FROM notifications")
    import socket
    settings["node_name"] = socket.getfqdn() + " / " + os.environ["MODULE_ID"]
    atomic_json(root / "config.json", settings)
    if settings["mode"] == "coordinator":
        route(settings)
    start(settings)
