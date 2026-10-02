#!/usr/bin/env bash
# Backwards-compatible wrapper — use ./build.sh (cross-platform).
exec "$(dirname "$0")/build.sh" "$@"
