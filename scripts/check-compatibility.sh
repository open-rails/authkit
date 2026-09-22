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

BASELINE_REF="$baseline" python3 - "$report/base" "$root" <<'PY'
from pathlib import Path
import json
import sys

old_root, new_root = map(Path, sys.argv[1:])
baseline_ref = __import__("os").environ["BASELINE_REF"]
old = old_root / "migrations/postgres"
new = new_root / "internal/migrations/postgres"
published = sorted(old.glob("*.sql"))
if not published:
    raise SystemExit("compatibility baseline has no migrations")
pre_v1 = baseline_ref.startswith("v0.")
for path in published:
    current = new / path.name
    # v0.x is the pre-v1 candidate line. Its single 0001 baseline is
    # intentionally editable until the owner freezes v1; all later releases
    # compare every published migration byte-for-byte.
    if pre_v1 and path.name == "1000_v1_schema.up.sql":
        # The pre-v1 baseline was renumbered to the conventional initial
        # migration name. Pre-v1 databases are disposable, so this is an
        # intentional identity hard cut rather than a compatibility promise.
        current = new / "0001_schema.up.sql"
        if not current.is_file():
            raise SystemExit(f"pre-v1 baseline migration removed or renamed unexpectedly: {path.name}")
        continue
    if not current.is_file() or current.read_bytes() != path.read_bytes():
        raise SystemExit(f"published migration changed or removed: {path.name}")
last = max(
    int(("0001_schema.up.sql" if p.name == "1000_v1_schema.up.sql" else p.name).split("_", 1)[0])
    for p in published
)
for path in new.glob("*.sql"):
    if pre_v1 and path.name == "0001_schema.up.sql":
        continue
    if not (old / path.name).exists() and int(path.name.split("_", 1)[0]) <= last:
        raise SystemExit(f"new migration must follow the baseline: {path.name}")
print(f"migration compatibility: {len(published)} published files unchanged")

def route_rows(root):
    return {line for line in (root / "docs/api-endpoints.md").read_text().splitlines()
            if line.startswith(tuple(f"| {method}" for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")))}

current_routes = route_rows(new_root)
removed = route_rows(old_root) - current_routes
# #380 deliberately makes authenticated membership discovery available even
# with only the intrinsic root persona. Its method/path/auth contract is intact;
# only this obsolete availability annotation is removed in the pre-v1 hard cut.
if pre_v1 and "| GET | `{api}/me/groups` | account | required |  |  |" in current_routes:
    removed.discard("| GET | `{api}/me/groups` | account | required |  | RBAC persona profile |")
# #379 retires the public erasure handoff/backlog in favor of constructor
# callbacks delivered durably by AuthKit. This one pre-v1 route is a hard cut.
if pre_v1:
    removed.discard("| GET | `{api}/admin/erasure/backlog` | admin | `root:resources:read` |  |  |")
if removed:
    raise SystemExit("published routes changed or removed:\n" + "\n".join(sorted(removed)))

def preserve(want, got, path):
    if isinstance(want, dict) and isinstance(got, dict):
        for key, value in want.items():
            if key not in got:
                raise SystemExit(f"published wire field removed: {path}.{key}")
            preserve(value, got[key], f"{path}.{key}")
    elif type(want) is not type(got) or want != got:
        raise SystemExit(f"published wire contract changed: {path}")

for fixture in (old_root / "authhttp/testdata/wire").glob("*.json"):
    current = new_root / "authhttp/testdata/wire" / fixture.name
    if not current.is_file():
        raise SystemExit(f"published wire fixture removed: {fixture.name}")
    preserve(json.loads(fixture.read_text()), json.loads(current.read_text()), fixture.name)
print("route and wire compatibility: published requirements preserved")
PY

tool=golang.org/x/exp/cmd/apidiff@v0.0.0-20260908205506-85c1c2202aba
export GOWORK=off GOFLAGS=-mod=readonly
for directory in . adapters/gin adapters/fiber; do
  name=${directory//\//_}
  module=$(cd "$root/$directory" && go list -m)
  # GOWORK=off alone does not disable module-local replacements.
  (cd "$root/$directory" && go mod edit -json) | python3 -c '
import json, sys
for replacement in json.load(sys.stdin).get("Replace", []) or []:
    raise SystemExit("module replacement defeats release validation: " + replacement["Old"]["Path"])
'
  if [[ -f "$report/base/$directory/go.mod" ]]; then
    # A historical module may need its indirect graph normalized by the current
    # Go toolchain. This writes only the extracted report copy, never a checkout.
    (cd "$report/base/$directory" && GOFLAGS=-mod=mod go run "$tool" -m -w "$report/$name.export" "$module")
    (cd "$root/$directory" && go run "$tool" -m -incompatible "$report/$name.export" "$module") > "$report/$name.diff"
    # v0.x is still the pre-v1 candidate line: exported API hard cuts are
    # intentional while the owner finalizes the contract. Keep the report for
    # review, but only enforce apidiff once the baseline is v1 or newer.
    if [[ -s "$report/$name.diff" && "$baseline" != v0.* ]]; then
      cat "$report/$name.diff"
      exit 1
    fi
    if [[ -s "$report/$name.diff" ]]; then
      printf 'Pre-v1 API hard cut permitted for %s; advisory diff retained at %s\n' "$module" "$report/$name.diff"
    fi
  else
    printf 'New module absent from compatibility baseline: %s\n' "$module"
  fi
  # Workspace workflows already run every adapter. Native HTTP routing bridges
  # must also execute against their published core dependency.
  if [[ "$directory" == adapters/fiber || "$directory" == adapters/gin ]]; then
    (cd "$root/$directory" && go test -race -count=1 ./... && go vet ./...)
  else
    (cd "$root/$directory" && go test -run '^$' ./...)
  fi
  printf 'Go compatibility: %s\n' "$module"
done
