#!/usr/bin/env bash
# Opt-in local commits only. Never pulls or pushes and never changes grants.
set -euo pipefail
[ "${BRAIN_AUTOCOMMIT:-0}" = 1 ] || exit 0
ROOT="${MY_BRAIN_DIR:-${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}}"
export MY_BRAIN_DIR="$ROOT"
[ -d "$ROOT/.git" ] || exit 0
# Only vault knowledge is owned by this hook; never stage system files or raw transcripts.
if [ -z "$(git -C "$ROOT" status --porcelain -- wiki research)" ]; then exit 0; fi
GIT_DIR="$(git -C "$ROOT" rev-parse --absolute-git-dir)"
if ! node "$ROOT/.tools/lint/lint.mjs" --gate; then
  printf 'Knowledge lint gate failed; autocommit held.\n' > "$GIT_DIR/lint-failed"
  exit 0
fi
# Refuse pre-staged work, which belongs to the operator or another session.
if ! git -C "$ROOT" diff --cached --quiet; then
  echo 'Autocommit held: operator-staged changes exist.' >&2
  exit 0
fi
git -C "$ROOT" add -- wiki research
if ! git -C "$ROOT" diff --cached --quiet; then
  git -C "$ROOT" commit -m 'auto(brain): update knowledge'
fi
rm -f "$GIT_DIR/lint-failed"
