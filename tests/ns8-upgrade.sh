#!/bin/bash
# Runs only inside the disposable CI VM: update the last release to the tested image.
set -Eeuo pipefail
previous="${1:?previous release image}"
image="${2:?module image}"
module="$(add-module "$previous" 1 | python3 -c 'import ast,sys; print(ast.literal_eval(sys.stdin.read())["module_id"])')"
api-cli run "module/$module/configure-module" --data \
    '{"mode":"coordinator","public_url":"https://bans.ns8.test","notifications":{"enabled":false}}'
runagent -m "$module" python3 /tmp/ns8-upgrade-seed.py
api-cli run update-module --data "{\"module_url\":\"$image\",\"instances\":[\"$module\"],\"force\":true}"
runagent -m "$module" python3 /tmp/ns8-upgrade-check.py

# Update the tested image onto itself: now its own update-module/04quiesce runs.
# NS8 extract-image chowns the module tree under `set -e`, so the services must
# be stopped before the image is extracted.
cursor="$(journalctl -n 0 --show-cursor | sed -n 's/^-- cursor: //p')"
api-cli run update-module --data "{\"module_url\":\"$image\",\"instances\":[\"$module\"],\"force\":true}"
journal="$(journalctl --after-cursor="$cursor" --no-pager -o cat)"
stopped="$(grep -n "Stopped NS8 Fail2ban worker ($module)" <<<"$journal" | head -n 1 | cut -d: -f1)"
extracted="$(grep -n "Extracting container filesystem imageroot to /var/lib/nethserver/$module" <<<"$journal" | head -n 1 | cut -d: -f1)"
if [[ -z "$stopped" || -z "$extracted" || "$stopped" -ge "$extracted" ]]; then
    echo "FAIL: services were not stopped before the image was extracted ($stopped, $extracted)" >&2
    exit 1
fi
echo 'PASS: services stop before the updated image is extracted'
if systemctl list-units --all --plain --no-legend "$module-update-resume*" | grep -q .; then
    echo 'FAIL: the update left its resume timer behind' >&2
    exit 1
fi
echo 'PASS: a successful update cancels the resume timer'
runagent -m "$module" python3 /tmp/ns8-upgrade-check.py
remove-module --no-preserve "$module"
if systemctl is-active --quiet "$module-worker.service"; then exit 1; fi
if nft list tables | grep -q 'ns8_f2b_'; then exit 1; fi
echo 'PASS: updated module is removed cleanly'
