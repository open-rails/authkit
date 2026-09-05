# Naming policy delivery

Owner: Codex `/root/authkit_enrollment_fix`.
Branch: `fix/naming-policy`.
Base: `dc65f11` (fetched `origin/master`, 2026-09-04).
Tracker: AuthKit #335, #336, #337; coordinated consumer acceptance #339.

Implement one configurable naming policy for immutable user/group identities: default 72-hour rename interval and 90-day UUID-bound former-name reservation/forwarding. Replace pre-launch permanent group tombstones and historical-user-name alias assumptions with atomic claims. Preserve existing actor admission and domain restrictions.

The parent agent owns #338 exact-UUID authorization/read/delete APIs in `fix/ak338-uuid-scopes`; this branch will integrate that prerequisite without duplicating those methods. No active naming implementation was present among fetched branches/open PRs at the initial census. Existing #292 actor-aware group rename validation is already on master and will be reused.

Validation will cover omission-aware configuration, exact clock boundaries, real PostgreSQL claim/rename/reclaim races, user and generated group HTTP behavior, and embedded consumers. No live provider/user operations are part of this work. Root owns merge and tracker closure.

Foundation: omission-aware public config, one pure normalization/evaluation contract,
standalone environment mapping, normalized embedded policy accessor and stable
renames-disabled/cooldown errors. Root and standalone/embedded construction tests
pass under `go test -race . ./cmd/authkit-server -run 'TestNaming|Test.*Error'`.
Runtime enforcement and atomic claims remain in progress; no reuse safety claim yet.

Runtime implementation now uses migration **0014_name_claims.up.sql**; master
claimed0013 for refresh GC indexes while this task was active. Prototype private
DBs ak_naming/ak_naming_v2 are not release evidence. Correct-prefix fixtures use
ak_naming_v3; the final bounded-lock schema is in private ak_naming_final. No
shared/production schema was reset or relabeled.

Implemented canonical/alias ownership, DB creation/update guards, user/group
owner-locked renames, exact request-time expiry, all registration/import checks,
shared host namespace admission, atomic UUID group settings and generated-route
request identity binding. Removed the unused UpdateUsernameForce primitive; no
new administrative bypass is exposed. Parent UUID APIs (#121) are integrated.

Real PG/race checks passed for user/group expiry/reclaim, overlapping owner renames,
create/rename competition, raw/import reservation protection, finite/forever/instant,
no-op/disabled policy, trusted import preservation, deletion+canonical-only release,
prospective policy changes, HTTP admission/composite PATCH and captured members,
keys, applications and invite paths. Full workspace validation is in progress;
initial full run found an unknown-group status regression (fixed) and was stopped
to bound per-name lock growth before the 100k performance fixture. Current source
is not yet declared merge-ready; first-party adoption remains #339/#949 work.


Final local evidence: the full workspace `go test -race -p 1
 github.com/open-rails/authkit/...` passed with DB-required and isolated Redis
leases after restoring explicit-vs-raw deletion semantics and replacing the
portable host-clock cooldown method with `UserNamingState`. The subsequent
bounded alias-maintenance hook, nil-store guards, imported-name no-op check and
dead-query removal passed targeted core/HTTP/DB/remote race tests, SQLC
generate+vet, staticcheck and govet. The 100k-row query-performance fixture
passed with the 256-stripe lock bound. Logs are under `.runtime/`.

API contract sent to the consumer owners: atomic `UpdateGroupInstanceAs`;
`UserNamingState` portable read; GET /me and rename responses report normalized
policy, eligibility and aliases with recorded deadlines. Root owns generic
machine scope #338 and final merging. SaaS PR62 is this agent's adoption lane;
Doujins/Hentai0 adoption belongs to `/root/refund_fixes`. Current Tensorhub and
final OpenRails acceptance remain recorded prerequisites, not inferred adoption.
