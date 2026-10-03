#!/usr/bin/env bash
# Optional Git Bash setup check; harvest only needs the sibling page-fetch.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
echo "[harvest setup] dir=$DIR"

IF="${PAGE_FETCH_DIR:-$DIR/../page-fetch}"
miss=0
[ -d "$IF" ] && echo "  ✓ page-fetch engine present" || { echo "  ✗ page-fetch MISSING ($IF)"; miss=1; }
[ "$miss" = 1 ] && { echo "[harvest setup] page-fetch missing"; exit 1; }

echo "[harvest setup] running smoke (offline)…"
if node test/smoke.mjs; then
  echo "[harvest setup] ✅ ready. Try: node harvest.mjs https://example.com"
else
  echo "[harvest setup] ❌ smoke failed"; exit 1
fi
