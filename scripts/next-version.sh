#!/usr/bin/env bash
# Compute the next date-based version tag: vYYYY.M.PATCH (no leading zero on month).
set -euo pipefail
TODAY="$(date +%Y.%-m)"
LATEST="$(git tag --list "v${TODAY}.*" 2>/dev/null | sort -V | tail -1)"
if [ -z "$LATEST" ]; then
  echo "v${TODAY}.0"
else
  PATCH="${LATEST##*.}"
  echo "v${TODAY}.$((PATCH + 1))"
fi
