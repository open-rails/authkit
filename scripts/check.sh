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
export GOWORK=off
go run ./internal/cmd/migrate \
	-dsn "$AUTHKIT_TEST_DATABASE_URL" -schema profiles

if [[ "$mode" != contracts ]]; then
  mkdir -p .reports
  export AUTHKIT_PLAYWRIGHT_MODULE=${AUTHKIT_PLAYWRIGHT_MODULE:-$PWD/internal/apitest/testdata/node_modules/@playwright/test}
  go test -race -count=1 -p 1 -tags browser -json ./... \
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
# Required by name, so a test can move between packages without an edit here.
required = ('TestSecurityAccessTokenForgery', 'TestSecurityBearerTransport', 'TestSecurityRefreshTokenTheft', 'TestSecurityTokenExchangeOutlivingRevocation',
            'TestSecurityRefreshHistoryIsBounded',
            'TestSecurityRefreshGraceDoesNotFork', 'TestSecuritySessionRevocationEvents',
            'TestSecurityPasswordChangeEndsOtherSessions', 'TestSecurityRevokedSessionCannotChangeCredentials',
            'TestSecuritySecondFactorLockout',
            'TestSecuritySecondFactorGuessBudget', 'TestSecurityUnbanRequiresAuthority',
            'TestSecurityRemoteApplicationTakeover', 'TestSecurityRoleEscalation', 'TestSecurityMultiReplicaStores',
            'TestSecurityClientAddressSpoofing', 'TestSecurityKeyRotationIsPublished',
            'TestSecurityRefreshCookieCSRF', 'TestSecurityRequestBoundary', 'TestSecurityAccountEnumeration',
            'TestSecurityUnprovenContactCannotAddLoginMethods', 'TestSecurityPreRegistrationTakeover',
            'TestSecurityRegistrationNeverSelfVerifies', 'TestSecurityProviderEmailTrust',
            'TestSecurityPasswordLimitIsPerAddress', 'TestSecurityDemotedCreatorCredentials',
            'TestSecurityRevokeAboveOwnRole', 'TestSecurityRemoteApplicationIssuerSquat',
            'TestSecurityAccountPeerRemoteApplication',
            'TestSecuritySystemApplicationRekey', 'TestSecurityGroupApplicationTrustRoot',
            'TestSecurityApplicationMFARoles', 'TestSecurityRemovedRoutesAreGone', 'TestSecurityTokenMatrix', 'TestSecurityRemoteApplicationPaging', 'TestSecurityBootstrapNeverAdoptsSquatters', 'TestSecurityEnsureUserRole', 'TestSecurityImportUsers',
            'TestSecurityImportSolanaLinks', 'TestSecurityLinkProvider', 'TestSecurityIssuerWithoutAudience',
            'TestSecurityOIDCStateCookieIsHostPrefixed', 'TestSecurityProviderIssuerCollisions',
            'TestSecurityInviteTokenNotInURL', 'TestSecurityProviderPKCE', 'TestSecurityFormPostCallbackIsBounded',
            'TestSecurityOutboundAddressGuard', 'TestSecurityPurgedUsernameStaysReserved',
            'TestSecurityRefreshCookieUpgrade', 'TestSecurityDeadCreatorCredentials', 'TestSecurityAccountAuthority',
            'TestSecurityContactChangeKeepsMFARoles', 'TestSecurityVerifiedOnlyByProof',
            'TestSecurityInlinePasswordNeedsSecondFactor', 'TestSecurityAccountLifecycleRevokesCredentials',
            'TestSecurityPasswordStepUpNeedsSecondFactor', 'TestSecurityDeviceKeyMFAGate',
            'TestSecurityApplicationRegistrar', 'TestSecurityFirstProofRevokesSquatterInvitations',
            'TestSecurityDeletionRecoveryIsSelfOnly', 'TestSecuritySelfRulesUseCanonicalIDs',
            'TestSecurityEnrollmentTokenOutsideMiddleware', 'TestSecurityMFARequirementRevokesMachineCredentials',
            'TestSecurityMemberEmailIsAnInvitation', 'TestSecurityContactChangeKeepsEnrolledMFA',
            'TestSecurityGroupLifecycleIsTheHosts', 'TestSecurityAPIKeysNeedPersonaOptIn',
            'TestSecurityDeviceKeyNeedsIndependentFactor', 'TestSecurityCredentialSweepNeverBlocksBoot',
            'TestSecurityEmailFactorIsPinned', 'TestSecurityGroupRoleIDsAreCanonical',
            'TestSecurityPasswordStepUpOnPasskeySession', 'TestSecurityStaffDeleteOverridesSelfDelete',
            'TestSecurityPasskeyHolderNeedsPasskey', 'TestSecurityVerifyRequestRevealsNothing',
            'TestSecurityUserManagementNeedsMFA', 'TestSecurityResetAccountMFA',
            'TestSecurityOwnApplicationIsNoReplacementOwner', 'TestSecurityEmailFactorFollowsOwnChange',
            'TestSecurityDeviceKeyRefusedBeforeBackupCode', 'TestSecurityRegistrationResendRevealsNothing',
            'TestSecurityDeviceKeyIndependentFactors', 'TestSecurityVerifyRequestByPhoneRevealsNothing',
            'TestSecurityDeviceKeyClient', 'TestSecurityImportProviders', 'TestSecurityImportedDeletionLifecycle',
            'TestSecurityUsernameChecks', 'TestSecuritySessionEventHistory', 'TestSecurityBasePathConfinesSurface',
            'TestSecurityEventsRecordOnlyCommittedChanges', 'TestSecurityEventsCarryNoSecrets',
            'TestSecurityGroupsJoinTheHostTransaction', 'TestSecurityLimiterOutageStaysLimited', 'TestSecurityReplicasShareRateLimits',
            'TestSecuritySecretsStayOutOfLogs', 'TestSecurityUnknownClientAddressIsLimited',
            'TestSecurityMutatingRoutesCheckTheSession', 'TestSecurityRevokedSessionAtLiveGates',
            'TestSecurityPerAppRoleCatalogs', 'TestSecurityPreRegistrationContactChange',
            'TestSecurityDisabledApplicationTokens', 'TestSecurityAdminDeleteIsNotSelfDelete',
            'TestSecurityPasswordHashingIsBounded', 'TestSecurityAPIKeyResolvesOnlyAtItsApp',
            'TestSecuritySignInLimits', 'TestSecuritySignInLimitsEdges',
            'TestSecurityAuthenticatorConformance', 'TestClientIsNotAnAuthenticator', 'TestSecurityIdentitySubjectInvokerCredential', 'TestSecurityIdentityStateIsAuthKits',
            'TestRoleOwnerWorkflow', 'TestGroupLifecycleWorkflow',
            'TestAccountDeletionGenerationOrderingAndFinalization',
            'TestAccountDeletionDeliveryAcrossSeparateRiverFleets',
            'TestAccountDeletionRollsBackWhenRiverInsertFails', 'TestAccountRecoveryAndFinalizerSerializeAtDeadline',
            'TestAccountCallbackFailureAndConcurrentRescue',
            'TestAccountLifecycleTerminalGCIsBoundedAndPreservesPendingWork',
            'TestAccountFleetRebindRequiresQuiescenceAndFencesOldProducer',
            'TestAccountCallbackCanObserveBindingDuringManagedShutdown',
            'TestRecoveryProofCannotCrossGenerationOrRaceFinalPurge', 'TestCookieRegistry',
            'TestAccountAdmissionWorkflow', 'TestAuthenticationContinuationWorkflow',
            'TestProviderAuthenticationWorkflow', 'TestNativeCredentialWorkflow', 'TestCookieLoginBrowserTwoSites',
            'TestWorkflowRateLimits',
            'TestStaffAccountRestoreHTTPRequiresCurrentAuthority', 'TestAccountRecoveryPasswordConfirmationBoundary',
            'TestAccountRecoveryUsesExistingCredentialAndMFACeremonies', 'TestNoCredentialOutlivesItsIssuer',
            'TestRoleCatalogChangesAtBoot', 'TestRemoteApplicationRegistry',
            'TestOAuthJWTBearerGrant', 'TestOAuthJWTBearerRefusals', 'TestOAuthDeviceKeyTokensGrantNothing')
passed = {e['Test'] for e in events if e.get('Action') == 'pass' and e.get('Test')}
missing = [name for name in required if name not in passed]
if missing:
    raise SystemExit(f'Missing workflow passes: {missing}')
print(f'Workflows qualified: {sum(1 for e in events if e.get("Action") == "pass" and e.get("Test"))} test/subtest passes, zero skips')
PY
fi

if [[ "$mode" != workflows ]]; then
  go vet ./...
  # auth-ui's e2e server builds AuthKit from this checkout: its module must
  # follow the root's requirements.
  (cd auth-ui/e2e/server && go mod tidy -diff)
  go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate -f internal/db/sqlc.yaml
  go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 vet -f internal/db/sqlc.yaml
  git diff --exit-code -- internal/db
  test -z "$(git ls-files --others --exclude-standard -- internal/db)"

  # Released migrations are immutable and new ones are numbered after them. A
  # squash keeps the released chain verbatim under internal/migrations/retired
  # (its conversion reads it) and restarts the numbering.
  migrations=internal/migrations/postgres
  release=$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD)
  last=0
  for path in $(git ls-tree --name-only "$release" -- "$migrations/" | grep '\.sql$'); do
    blob=$(git rev-parse "$release:$path")
    number=$(basename "$path")
    number=${number%%_*}
    if [[ -f $path && $(git hash-object "$path") == "$blob" ]]; then
      if (( 10#$number > last )); then last=$((10#$number)); fi
    elif ! git hash-object internal/migrations/retired/*/"$(basename "$path")" 2>/dev/null | grep -qx "$blob"; then
      echo "migration $path released in $release was changed or removed; a squash keeps it verbatim under internal/migrations/retired" >&2
      exit 1
    fi
  done
  for added in $(git diff --name-only --diff-filter=A "$release" -- "$migrations/*.sql"); do
    number=$(basename "$added")
    number=${number%%_*}
    if (( 10#$number <= last )); then
      echo "new migration $added must be numbered after $last (released in $release)" >&2
      exit 1
    fi
  done
fi
