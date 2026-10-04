#!/bin/bash
# Runs only inside the disposable CI VM, after ns8-smoke.sh and the browser check.
set -Eeuo pipefail
module="$(cat /tmp/fail2ban-module-id)"
remove-module --no-preserve "$module"
if systemctl is-active --quiet "$module-worker.service"; then exit 1; fi
if nft list tables | grep -q 'ns8_f2b_'; then exit 1; fi
echo 'PASS: NS8 removal cleans up services, proxy route and module firewall'
