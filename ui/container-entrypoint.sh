#!/bin/bash

set -Eeuo pipefail

case "${1:-}" in
    watch|build)
        yarn install --immutable
        exec yarn "$1"
        ;;
    "")
        echo "Missing parameter: append 'watch' or 'build'." >&2
        exit 64
        ;;
    *)
        echo "Unsupported parameter '$1'; expected 'watch' or 'build'." >&2
        exit 64
        ;;
esac
