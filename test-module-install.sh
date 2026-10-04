#!/bin/bash

# SPDX-License-Identifier: GPL-3.0-or-later

set -Eeuo pipefail

exec bash "$(dirname "$0")/test-module.sh" \
    "${1:?missing leader node address}" \
    "${2:?missing module image URL}" \
    install
