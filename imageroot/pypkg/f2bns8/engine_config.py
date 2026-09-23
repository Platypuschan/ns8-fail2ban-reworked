"""Create the exact Fail2ban configuration used by the packaged engine."""
import shutil
from pathlib import Path
from .common import JAILS


def generate(state, root, upstream, action):
    state, root = Path(state), Path(root)
    (state / "logs").mkdir(parents=True, exist_ok=True)
    for jail in JAILS:
        (state / "logs" / (jail + ".log")).touch(exist_ok=True)
    shutil.copytree(upstream, root, dirs_exist_ok=True)
    (root / "action.d/ns8.py").write_text(Path(action).read_text())
    (root / "filter.d/ns8.conf").write_text('[Definition]\nfailregex = ^<HOST> \\{.*\\}$\nignoreregex =\ndatepattern = {^LN-BEG}%%Y-%%m-%%dT%%H:%%M:%%S%%z\n')
    (root / "fail2ban.local").write_text('[Definition]\nlogtarget = STDOUT\nsocket = ' + str(state / "fail2ban.sock")
        + '\npidfile = ' + str(root / 'fail2ban.pid') + '\ndbfile = ' + str(state / 'fail2ban.sqlite3') + '\ndbpurgeage = 0\ndbmaxmatches = 50\n')
    content = '[DEFAULT]\nenabled = false\nbackend = polling\nbantime = -1\nfindtime = 600\nmaxretry = 5\nusedns = no\nignoreself = false\nignoreip = 127.0.0.0/8 ::1\nfilter = ns8\naction = ns8.py\n'
    for jail in JAILS:
        content += '\n[' + jail + ']\nenabled = true\nlogpath = ' + str(state / 'logs' / (jail + '.log')) + '\n'
    (root / "jail.conf").write_text(content)
    shutil.rmtree(root / "jail.d", ignore_errors=True)
