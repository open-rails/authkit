#!/usr/bin/env bash
# One local/CI entrypoint: real workflows, contract checks, or both.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-all}
case "$mode" in all|workflows|contracts) ;; *) echo 'usage: scripts/check.sh [all|workflows|contracts]' >&2; exit 2 ;; esac

if [[ -z "${AUTHKIT_TEST_DATABASE_URL:-}" ]]; then
  docker compose up -d --wait postgres redis
  export AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable'
fi
export AUTHKIT_TEST_REDIS_URL=${AUTHKIT_TEST_REDIS_URL:-redis://127.0.0.1:36379/0}
export AUTHKIT_TEST_REQUIRE_DB=1
# AuthKit's SQL is schema-neutral; sqlc's live PREPARE checks must resolve it
# against the same default namespace used by the integration pool.
if [[ "$AUTHKIT_TEST_DATABASE_URL" == *\?* ]]; then
  sqlc_sep='&'
else
  sqlc_sep='?'
fi
export SQLC_DATABASE_URL="${AUTHKIT_TEST_DATABASE_URL}${sqlc_sep}options=-csearch_path%3Dprofiles%2Cpublic"
export GOMAXPROCS=${GOMAXPROCS:-2}
go run ./cmd/authkit-migrate \
	-dsn "$AUTHKIT_TEST_DATABASE_URL" -schema profiles

if [[ "$mode" != contracts ]]; then
  mkdir -p .reports
  export AUTHKIT_PLAYWRIGHT_MODULE=${AUTHKIT_PLAYWRIGHT_MODULE:-$PWD/authhttp/testdata/node_modules/@playwright/test}
  go test -race -count=1 -p 1 -tags browser -json github.com/open-rails/authkit/... \
    | tee .reports/go-test.json | jq -rj 'select(.Output != null) | .Output'
  python3 - <<'PY'
import json
from pathlib import Path
events = [json.loads(line) for line in Path('.reports/go-test.json').read_text().splitlines()
          if line.startswith('{')]
bad = [e for e in events if e.get('Action') in ('fail', 'build-fail')
       or (e.get('Action') == 'skip' and e.get('Test'))]
if bad:
    raise SystemExit(f'Unqualified workflows: {bad}')
required = {
    'authhttp': ('TestAccountAdmissionWorkflow', 'TestAuthenticationContinuationWorkflow',
                 'TestProviderAuthenticationWorkflow', 'TestNativeCredentialWorkflow',
                 'TestCookieLoginBrowserTwoSites', 'TestBrowserDelegationWorkflow',
                 'TestWorkflowRateLimits', 'TestOperatorAccountRestoreHTTPRequiresCurrentAuthority',
                 'TestAccountRecoveryPasswordConfirmationBoundary',
                 'TestAccountRecoveryUsesExistingCredentialAndMFACeremonies'),
    'embedded': ('TestRoleOwnerWorkflow', 'TestGroupLifecycleWorkflow',
                 'TestAccountDeletionGenerationOrderingAndFinalization',
                 'TestAccountDeletionDeliveryAcrossSeparateRiverFleets',
                 'TestAccountDeletionRollsBackWhenRiverInsertFails',
                 'TestAccountRecoveryAndFinalizerSerializeAtDeadline',
                 'TestAccountCallbackFailureAndConcurrentRescue',
                 'TestAccountLifecycleTerminalGCIsBoundedAndPreservesPendingWork',
                 'TestAccountFleetRebindRequiresQuiescenceAndFencesOldProducer',
                 'TestAccountCallbackCanObserveBindingDuringManagedShutdown',
                 'TestRecoveryProofCannotCrossGenerationOrRaceFinalPurge'),
}
passed = {(e.get('Package'), e.get('Test')) for e in events if e.get('Action') == 'pass'}
missing = [f'{pkg}/{name}' for pkg, tests in required.items() for name in tests
           if (f'github.com/open-rails/authkit/{pkg}', name) not in passed]
if missing:
    raise SystemExit(f'Missing workflow passes: {missing}')
print(f'Workflows qualified: {sum(bool(test) for _, test in passed)} test/subtest passes, zero skips')
PY
fi

if [[ "$mode" != workflows ]]; then
  go vet github.com/open-rails/authkit/...
  go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
  go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 vet
  git diff --exit-code -- internal/db
  test -z "$(git ls-files --others --exclude-standard -- internal/db)"
  scripts/check-compatibility.sh
fi
