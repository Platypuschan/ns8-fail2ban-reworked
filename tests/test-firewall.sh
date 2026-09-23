#!/bin/bash
# The runner's own network/firewall is untouched: everything is inside unshare.
set -euo pipefail
if [[ "${1:-}" != isolated ]]; then
    exec unshare --net --mount --propagation private bash "$0" isolated
fi
task_ns_left="f2b-left-$$"
task_ns_right="f2b-right-$$"
task_state="$(mktemp -d)"
cleanup() {
    ip netns del "${task_ns_left}" || true
    ip netns del "${task_ns_right}" || true
    rm -rf "${task_state}"
}
trap cleanup EXIT
ip link set lo up
ip netns add "${task_ns_left}"
ip netns add "${task_ns_right}"
for side in left right; do
    if [[ "$side" == left ]]; then ns="$task_ns_left"; subnet=10; else ns="$task_ns_right"; subnet=20; fi
    ip link add "v-$side" type veth peer name peer
    ip link set peer netns "$ns"
    ip addr add "192.0.$subnet.1/24" dev "v-$side"
    ip -6 addr add "2001:db8:$subnet::1/64" dev "v-$side" nodad
    ip link set "v-$side" up
    ip -n "$ns" link set lo up
    ip -n "$ns" addr add "192.0.$subnet.2/24" dev peer
    ip -n "$ns" -6 addr add "2001:db8:$subnet::2/64" dev peer nodad
    ip -n "$ns" link set peer up
    ip -n "$ns" route add default via "192.0.$subnet.1"
    ip -n "$ns" -6 route add default via "2001:db8:$subnet::1"
done
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec "$task_ns_left" ping -c 1 -W 2 192.0.20.2
ip netns exec "$task_ns_left" ping -6 -c 1 -W 2 2001:db8:20::2
export F2B_STATE_DIR="$task_state"
python3 - <<'PY'
from f2bns8.firewall import apply
apply('fail2ban-test', ['192.0.10.2', '2001:db8:10::2'])
PY
must_block() {
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: banned traffic passed: $*" >&2
        exit 1
    fi
}
must_block ip netns exec "$task_ns_left" ping -c 1 -W 1 192.0.10.1
must_block ping -c 1 -W 1 192.0.10.2
must_block ip netns exec "$task_ns_left" ping -c 1 -W 1 192.0.20.2
must_block ip netns exec "$task_ns_right" ping -c 1 -W 1 192.0.10.2
must_block ip netns exec "$task_ns_left" ping -6 -c 1 -W 1 2001:db8:10::1
must_block ping -6 -c 1 -W 1 2001:db8:10::2
must_block ip netns exec "$task_ns_left" ping -6 -c 1 -W 1 2001:db8:20::2
must_block ip netns exec "$task_ns_right" ping -6 -c 1 -W 1 2001:db8:10::2
python3 - <<'PY'
from f2bns8.firewall import apply
apply('fail2ban-test', [])
PY
ip netns exec "$task_ns_left" ping -c 1 -W 2 192.0.20.2
ip netns exec "$task_ns_left" ping -6 -c 1 -W 2 2001:db8:20::2
echo 'PASS: IPv4/IPv6 input, output, forwarding and manual unban'
