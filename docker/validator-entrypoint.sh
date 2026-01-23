#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="/out"
ART_DIR="${OUT_DIR}/artifacts"
mkdir -p "$ART_DIR"

cp -v /debs/*.deb "$ART_DIR" || true

PKG_BIN="${1:-}"
if [ -n "$PKG_BIN" ] && command -v "$PKG_BIN" >/dev/null 2>&1; then
  "$PKG_BIN" --version || true
else
  if [ -n "$PKG_BIN" ]; then
    dpkg -l | grep -E "^ii\s+${PKG_BIN}\s" || true
  else
    dpkg -l | grep -E "^ii\s+" || true
  fi
fi

echo "Smoke test complete"
