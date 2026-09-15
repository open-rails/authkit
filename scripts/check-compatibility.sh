#!/usr/bin/env bash
# Compare against an explicit release/candidate, including modules outside go.work.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
baseline=${1:-$(cat compatibility/base-ref)}
sha=$(git rev-parse --verify "${baseline}^{commit}")
report="$root/.reports/compatibility/$sha"
mkdir -p "$report/base"
git archive "$sha" | tar -x -C "$report/base"

python3 - "$report/base" "$root" <<'PY'
from pathlib import Path
import sys

old, new = (Path(p) / "migrations/postgres" for p in sys.argv[1:])
published = sorted(old.glob("*.sql"))
if not published:
    raise SystemExit("compatibility baseline has no migrations")
for path in published:
    current = new / path.name
    if not current.is_file() or current.read_bytes() != path.read_bytes():
        raise SystemExit(f"published migration changed or removed: {path.name}")
last = max(int(p.name.split("_", 1)[0]) for p in published)
for path in new.glob("*.sql"):
    if not (old / path.name).exists() and int(path.name.split("_", 1)[0]) <= last:
        raise SystemExit(f"new migration must follow the baseline: {path.name}")
print(f"migration compatibility: {len(published)} published files unchanged")
PY

tool=golang.org/x/exp/cmd/apidiff@v0.0.0-20260908205506-85c1c2202aba
export GOWORK=off GOFLAGS=-mod=readonly
for directory in . adapters/gin adapters/riverjobs; do
  name=${directory//\//_}
  module=$(cd "$root/$directory" && go list -m)
  # A historical module may need its indirect graph normalized by the current
  # Go toolchain. This writes only the extracted report copy, never a checkout.
  (cd "$report/base/$directory" && GOFLAGS=-mod=mod go run "$tool" -m -w "$report/$name.export" "$module")
  (cd "$root/$directory" && go run "$tool" -m -incompatible "$report/$name.export" "$module") > "$report/$name.diff"
  # apidiff reports incompatibilities on stdout without a nonzero exit status.
  if [[ -s "$report/$name.diff" ]]; then
    cat "$report/$name.diff"
    exit 1
  fi
  # Compile supported host examples and adapter tests using published requirements.
  (cd "$root/$directory" && go test -run '^$' ./...)
  printf 'Go compatibility: %s\n' "$module"
done
