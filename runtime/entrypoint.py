#!/usr/bin/env python3
import os
from f2bns8.engine_config import generate

generate("/state", "/run/fail2ban/config", "/opt/fail2ban/config", "/opt/ns8_action.py")
os.execvp("python3", ["python3", "/opt/fail2ban/bin/fail2ban-server", "-c", "/run/fail2ban/config", "-f", "start"])
