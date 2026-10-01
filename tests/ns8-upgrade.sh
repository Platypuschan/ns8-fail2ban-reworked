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
remove-module --no-preserve "$module"
if systemctl is-active --quiet "$module-worker.service"; then exit 1; fi
if nft list tables | grep -q 'ns8_f2b_'; then exit 1; fi
echo 'PASS: updated module is removed cleanly'
