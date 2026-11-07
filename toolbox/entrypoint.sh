#!/bin/sh
# Only the toolbox's own programs run here. HOME lives on the tmpfs Crenel
# mounts at /tmp (the root filesystem is read-only).
set -eu
mkdir -p "$HOME"
case "${1:-}" in
  nuclei|katana|trufflehog|socat) exec "$@" ;;
  *) echo "crenel-toolbox: only nuclei, katana, trufflehog (and the socat relay) run in this image" >&2; exit 64 ;;
esac
