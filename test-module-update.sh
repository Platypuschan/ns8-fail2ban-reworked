#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later

# Update the last published release to the image under test, the same path an
# NS8 Software Center update takes. PREVIOUS_IMAGE_URL overrides the release.

set -Eeuo pipefail

cd "$(dirname "$0")"
IMAGE_URL="${2:?missing module image URL}"
if [[ -z "${PREVIOUS_IMAGE_URL:-}" ]]; then
    PREVIOUS_IMAGE_URL="$(python3 .github/scripts/previous-release "${IMAGE_URL%:*}")"
fi
export PREVIOUS_IMAGE_URL

exec bash ./test-module.sh \
    "${1:?missing leader node address}" \
    "${IMAGE_URL}" \
    update
