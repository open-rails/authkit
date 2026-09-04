# Naming policy delivery

Owner: Codex `/root/authkit_enrollment_fix`.
Branch: `fix/naming-policy`.
Base: `dc65f11` (fetched `origin/master`, 2026-09-04).
Tracker: AuthKit #335, #336, #337; coordinated consumer acceptance #339.

Implement one configurable naming policy for immutable user/group identities: default 72-hour rename interval and 90-day UUID-bound former-name reservation/forwarding. Replace pre-launch permanent group tombstones and historical-user-name alias assumptions with atomic claims. Preserve existing actor admission and domain restrictions.

The parent agent owns #338 exact-UUID authorization/read/delete APIs in `fix/ak338-uuid-scopes`; this branch will integrate that prerequisite without duplicating those methods. No active naming implementation was present among fetched branches/open PRs at the initial census. Existing #292 actor-aware group rename validation is already on master and will be reused.

Validation will cover omission-aware configuration, exact clock boundaries, real PostgreSQL claim/rename/reclaim races, user and generated group HTTP behavior, and embedded consumers. No live provider/user operations are part of this work. Root owns merge and tracker closure.
