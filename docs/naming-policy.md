# User and group naming

AuthKit identifies users and group instances by immutable UUID. A persona is a
schema/type, not a group instance. Usernames and `(persona, slug)` remain separate
namespaces. Public routes resolve a current name or active alias to one UUID;
authorization and the operation must retain that same UUID.

## Configuration

`embedded.Config.Naming` accepts `authkit.NamingConfig`. Omitted fields mean
renames enabled, a 72-hour interval between successful renames, and finite
former-name retention of 2160 hours (90 × 24 hours, independent of DST).

```go
// Defaults:
cfg.Naming = authkit.NamingConfig{}
// Disable ordinary renames:
enabled := false
cfg.Naming = authkit.NamingConfig{Enabled: &enabled}
// Any frequency, retaining former names for the default 90 days:
interval := time.Duration(0)
cfg.Naming = authkit.NamingConfig{RenameInterval: &interval}
// Normal frequency with permanent former-name reservations:
cfg.Naming = authkit.NamingConfig{
    FormerNames: authkit.FormerNameRetentionConfig{Mode: authkit.FormerNamesForever},
}
// Any frequency with immediate release:
cfg.Naming = authkit.NamingConfig{
    RenameInterval: &interval,
    FormerNames: authkit.FormerNameRetentionConfig{Mode: authkit.FormerNamesImmediate},
}
```

The standalone server maps these environment variables to the identical config:

| Variable | Default | Examples |
| --- | --- | --- |
| `AUTHKIT_NAMING_ENABLED` | `true` | `false` |
| `AUTHKIT_NAMING_RENAME_INTERVAL` | `72h` | `0s`, `24h` |
| `AUTHKIT_NAMING_FORMER_NAMES_MODE` | `finite` | `forever`, `immediate` |
| `AUTHKIT_NAMING_FORMER_NAMES_DURATION` | `2160h` when finite | `0s`, `720h` |

Omit a variable to use its default. Present empty booleans/durations are invalid.
An empty retention object, or `finite` without duration, uses 2160h. A duration
without mode means finite; finite zero normalizes to immediate. Forever and
immediate reject **any** supplied duration, including zero. Negative values,
unknown modes, malformed durations, and duration overflow fail construction.
`Client.NamingPolicy()` returns the normalized values; durations in its JSON are
nanoseconds, following Go's `time.Duration` representation.

## Runtime contract

The first rename has no delay. A successful rename at T permits another at
T+interval. Failed attempts and authorized no-ops do not advance the timestamp.
The cooldown belongs to the identity, not its current owner or session. There is
no exposed administrative force-rename bypass. The unused core force method was
removed. Trusted import updates remain explicit provisioning operations: they can
change imported names while renames are disabled, but preserve UUID ownership,
reservation exclusivity, host name admission, and rename history.
Root and domain-managed groups retain their independent rename restrictions.

Aliases point directly to UUIDs and report the owner's current canonical name.
Finite aliases resolve and block another owner only while `now < expires_at`;
at the deadline they stop resolving and become claimable. Expiry is enforced on
request lookup and claim, without a cleanup job. Rename-back to an owned alias
obeys the same policy and gives the outgoing name a new deadline; unrelated
aliases retain their original deadlines. Policy changes affect future aliases,
not already-issued promises. Disabling renames does not disable forwarding.

Deletion does not forward to a dead identity and does not prematurely free old
rename reservations. Canonical-name deletion/release remains a separate explicit
lifecycle operation. API writes resolve aliases internally, preserving method and
body; no redirect is required. Credentials and internal jobs remain UUID-bound.

## Delivery status

This implements the AuthKit #335–#337 policy, storage and mutation contract. Stable
machine permission scopes (#338) and first-party adoption (#339; OpenRails
#947–#949) remain coordinated release prerequisites. Library tests or a published
artifact alone do not establish fleet adoption.

## Storage and request ownership

`profiles.name_claims` owns each normalized `(owner_kind, persona, name)` key.
A row carries owner UUID, canonical/alias state, and its persisted alias deadline.
A partial unique index permits one canonical name per owner. Creation claims and
inserts the identity in one statement; database triggers cover raw provisioning
and refuse direct name/UUID changes outside an atomic transition. User/group
renames lock the owner, re-read its actual name, then change claims and identity
inside the same transaction. Namespace locks use 256 consistently ordered stripes
to bound shared-memory locks even during large imports; collisions only serialize
unrelated claims. Bulk import retains insert-or-skip semantics for reserved names.

The migration preserves current development identities by their existing UUIDs.
It replaces permanent group tombstones and does not reinterpret user rename
history as live aliases. There is no dual registry, historical-alias backfill or
background expiry authority. Resolver reads are uncached and check deadlines on
every call, so restarts cannot extend an alias promise.

Generated group routes capture an immutable target before permission checks. A
request-local binding matches only that original persona/reference; subsequent
operation lookups recheck the captured group's liveness and never fall back to a
new owner of its name. Other targets and parent-group lookups remain independent.
`GroupByLiveInstanceSlug` is deliberately limited to the old trusted slug-delete
entry point; captured lifecycle retries use `DeleteGroupInstanceByID`.

`UpdateGroupInstanceAs(ctx, actorID, groupID, authkit.GroupInstanceUpdate)` replaces
the old rename-only facade. Slug and display-name changes commit together against
the captured UUID. Generated responses report `group_id`, current `instance_slug`,
and naming eligibility; group route headers report `X-AuthKit-Group-ID` and
`X-AuthKit-Canonical-Instance`. `ResolveUsername` exposes current name, owner UUID,
alias status and expiry. GET /me and username PATCH expose normalized `naming`
state; existing availability fields reflect the current deployment policy.

`WithNameAdmission` is a side-effect-free namespace predicate with operation,
owner UUID, actor and outgoing/requested names. It runs for generated creation
and ordinary rename. `WithInstanceAdmission` remains the separate creation-only
cost/enrollment hook and is never rerun by a rename. Trusted imports retain their
existing provisioning authority, but cannot bypass claim ownership.

The portable `UserNamingState(ctx,userID)` read replaces the old host-clock
`TimeUntilUsernameRenameAvailable` API; no independent policy arithmetic remains
on that surface. `CleanupExpiredAuthState` removes at most 5000 expired aliases
per call through an expiry index, preserving canonical and permanent claims.
This existing maintenance hook only removes stale storage; it never controls
forwarding or claim eligibility.
