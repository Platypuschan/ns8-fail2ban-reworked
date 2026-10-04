#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later

# Run the NS8 tests against a leader node over SSH. The CI calls this from
# NethServer/ns8-github-actions test-on-qemu.yml through test-module-install.sh
# and test-module-update.sh; the node needs nothing but a reachable SSH port.

set -Eeuo pipefail

LEADER_NODE="${1:?missing leader node address}"
IMAGE_URL="${2:?missing module image URL}"
SCENARIO="${3:?missing test scenario}"
PREVIOUS_IMAGE_URL="${PREVIOUS_IMAGE_URL:-}"
SSH_KEYFILE="${SSH_KEYFILE:-${HOME}/.ssh/id_ecdsa}"

case "${SCENARIO}" in
    install) ;;
    update)
        if [[ -z "${PREVIOUS_IMAGE_URL}" ]]; then
            echo "The update scenario needs PREVIOUS_IMAGE_URL; run test-module-update.sh." >&2
            exit 64
        fi
        ;;
    *)
        echo "Unsupported test scenario '${SCENARIO}'; expected install or update." >&2
        exit 64
        ;;
esac

if [[ ! -r "${SSH_KEYFILE}" ]]; then
    echo "SSH key is not readable: ${SSH_KEYFILE}" >&2
    exit 66
fi

ssh_node() {
    ssh -i "${SSH_KEYFILE}" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=10 -o ServerAliveInterval=30 \
        "root@${LEADER_NODE}" "$@"
}

mkdir -p tests/outputs
for name in ns8-smoke.py ns8-smoke.sh ns8-remove.sh ns8-notify-sink.py \
    ns8-upgrade.sh ns8-upgrade-seed.py ns8-upgrade-check.py; do
    ssh_node "cat > /tmp/${name}" <"tests/${name}"
done

if [[ "${SCENARIO}" == "update" ]]; then
    echo "Update scenario: ${PREVIOUS_IMAGE_URL} -> ${IMAGE_URL}"
    ssh_node bash /tmp/ns8-upgrade.sh "${PREVIOUS_IMAGE_URL}" "${IMAGE_URL}"
    exit 0
fi

ssh_node bash /tmp/ns8-smoke.sh "${IMAGE_URL}"

# Open the module UI in a real browser while the configured instance exists.
ui_venv="${RUNNER_TEMP:-/tmp}/f2b-ui-venv"
if [[ ! -x "${ui_venv}/bin/python" ]]; then
    python3 -m venv "${ui_venv}"
    "${ui_venv}/bin/pip" install --quiet playwright==1.63.0
    "${ui_venv}/bin/python" -m playwright install --with-deps chromium
fi
"${ui_venv}/bin/python" tests/ns8-ui-check.py "https://${LEADER_NODE}" \
    "$(ssh_node cat /tmp/fail2ban-module-id)" tests/outputs

ssh_node bash /tmp/ns8-remove.sh
