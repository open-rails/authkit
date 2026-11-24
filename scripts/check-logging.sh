#!/usr/bin/env bash
# AuthKit logs only through the *slog.Logger it is given: outside internal/logx
# and package main, no default slog logger and no standard-library log. Tests
# may log as they like.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
refuse() {
  printf '%s\n' "$1" >&2
  status=1
}
while IFS= read -r file; do
  [[ -e "$file" ]] || continue
  [[ "$file" == *_test.go || "$file" == internal/logx/* ]] && continue
  grep -q '^package main$' "$file" && continue
  if grep -vE '^\s*//' "$file" | grep -qE '\bslog\.(Default|SetDefault|Log|LogAttrs|(Debug|Info|Warn|Error)(Context)?)\('; then
    refuse "$file: uses the default slog logger; log through the injected *slog.Logger (only internal/logx and package main may)"
  fi
  if grep -qE '^\s*(import\s+)?([A-Za-z_][A-Za-z0-9_]*\s+)?"log"\s*$' "$file"; then
    refuse "$file: imports the standard library log; only package main may"
  fi
done < <(git ls-files -- '*.go' ':!:**/node_modules/**')
exit "$status"
