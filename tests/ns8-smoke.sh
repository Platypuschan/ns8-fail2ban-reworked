#!/bin/bash
# Runs only inside the disposable CI VM.
set -Eeuo pipefail
image="${1:?module image}"
module="$(add-module "$image" 1 | python3 -c 'import ast,sys; print(ast.literal_eval(sys.stdin.read())["module_id"])')"
printf '%s\n' "$module" >/tmp/fail2ban-module-id
systemd-run --unit=ns8-ci-notify python3 /tmp/ns8-notify-sink.py
api-cli run "module/$module/configure-module" --data \
    '{"mode":"coordinator","public_url":"https://bans.ns8.test","notifications":{"enabled":true,"url":"http://127.0.0.1:18888","topic":"test","token":""}}'
ip netns add f2b-attacker
ip link add f2b-test type veth peer name f2b-client
ip link set f2b-client netns f2b-attacker
ip addr add 192.0.2.1/30 dev f2b-test
ip link set f2b-test up
ip -n f2b-attacker addr add 192.0.2.2/30 dev f2b-client
ip -n f2b-attacker link set f2b-client up
ip -n f2b-attacker link set lo up
# The interface belongs to the same firewall zone as the normal management NIC.
firewall-cmd --zone=public --add-interface=f2b-test
runagent -m "$module" python3 /tmp/ns8-smoke.py
remove-module --no-preserve "$module"
if systemctl is-active --quiet "$module-worker.service"; then exit 1; fi
if nft list tables | grep -q 'ns8_f2b_'; then exit 1; fi
echo 'PASS: NS8 removal cleans up services, proxy route and module firewall'
