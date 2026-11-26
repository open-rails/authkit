#!/usr/bin/env bash
# One local/CI entrypoint: real workflows, contract checks, both, or the
# service-free light checks to run before pushing.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-all}
case "$mode" in all|workflows|contracts|light) ;; *) echo 'usage: scripts/check.sh [all|workflows|contracts|light]' >&2; exit 2 ;; esac
export GOMAXPROCS=${GOMAXPROCS:-2}
export GOWORK=off

if [[ "$mode" != light ]]; then
  if [[ -z "${AUTHKIT_TEST_DATABASE_URL:-}" ]]; then
    docker compose up -d --wait postgres redis
    export AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable'
  fi
  export AUTHKIT_TEST_REDIS_URL=${AUTHKIT_TEST_REDIS_URL:-redis://127.0.0.1:36379/0}
  export AUTHKIT_TEST_REQUIRE_DB=1
  export NOTIFY_TEST_DATABASE_URL="$AUTHKIT_TEST_DATABASE_URL"
fi

if [[ "$mode" == all || "$mode" == workflows ]]; then
  # Every package; each test makes its own schema, so journeys run in
  # parallel. Explicit -timeout: they run for minutes.
  mkdir -p .reports
  go test -race -count=1 -p 1 -parallel 4 -timeout 20m -json ./... \
    | tee .reports/go-test.json | jq -rj 'select(.Output != null) | .Output'
  python3 scripts/check_critical_results.py .reports/go-test.json
fi

if [[ "$mode" != workflows ]]; then
  scripts/check-logging.sh
  go run ./scripts/criticalcheck
  go vet ./...
  # auth-ui's e2e server builds AuthKit from this checkout: its module must
  # follow the root's requirements.
  (cd auth-ui/e2e/server && go mod tidy -diff)
  if [[ "$mode" == light ]]; then
    (cd auth-ui/e2e/server && go build ./...)
  else
    # sqlc prepares every query against PostgreSQL. AuthKit's SQL is
    # schema-neutral: a migrated schema on the search path resolves it.
    if [[ "$AUTHKIT_TEST_DATABASE_URL" == *\?* ]]; then
      sqlc_sep='&'
    else
      sqlc_sep='?'
    fi
    export SQLC_DATABASE_URL="${AUTHKIT_TEST_DATABASE_URL}${sqlc_sep}options=-csearch_path%3Dprofiles%2Cpublic"
    go run ./internal/cmd/migrate \
      -dsn "$AUTHKIT_TEST_DATABASE_URL" -schema profiles \
      -legacy-tenant-id 00000000-0000-4000-8000-000000000001
    go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate -f internal/db/sqlc.yaml
    go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 vet -f internal/db/sqlc.yaml
    git diff --exit-code -- internal/db
    test -z "$(git ls-files --others --exclude-standard -- internal/db)"
  fi

  scripts/check-released-migrations.sh
fi
