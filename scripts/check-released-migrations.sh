#!/usr/bin/env bash
# Released migrations are immutable: every migration file the latest release
# shipped is byte-identical here, and a new one is numbered after them. A
# schema change is a new migration.
set -euo pipefail
cd "$(dirname "$0")/.."

dirs=(internal/migrations/postgres notify/postgres/migrations)
# v1.58.0's baselines replaced every earlier chain; older releases are not compared.
first=v1.58.0

latest=$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null || true)
if [[ -z "$latest" || "$(printf '%s\n%s\n' "$first" "$latest" | sort -V | head -1)" != "$first" ]]; then
  echo "No release from $first on; nothing to compare."
  exit 0
fi
for dir in "${dirs[@]}"; do
  released=$(git ls-tree --name-only "$latest" -- "$dir/" | grep '\.sql$' || true)
  last=0
  for path in $released; do
    if [[ ! -f $path || $(git hash-object "$path") != $(git rev-parse "$latest:$path") ]]; then
      echo "migration $path released in $latest was changed or removed; add a new migration" >&2
      exit 1
    fi
    number=$(basename "$path")
    number=$((10#${number%%_*}))
    if (( number > last )); then last=$number; fi
  done
  for path in "$dir"/*.sql; do
    if grep -qxF "$path" <<<"$released"; then continue; fi
    number=$(basename "$path")
    number=$((10#${number%%_*}))
    if (( number <= last )); then
      echo "new migration $path must be numbered after $last (released in $latest)" >&2
      exit 1
    fi
  done
done
echo "The migrations released in $latest are unchanged."
