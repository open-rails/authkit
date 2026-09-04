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
The cooldown belongs to the identity, not its current owner or session. Support
force operations can bypass enabled/cooldown checks with existing administrative
authority and audit, never namespace ownership or another identity's reservation.
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

The policy/configuration foundation is implemented first in AuthKit #335. Runtime
claim storage (#336), mutation authorization (#337), UUID permission scopes (#338),
and coordinated first-party adoption (#339; OpenRails #947–#949) must land before
finite or immediate name reuse is enabled. This foundation alone does not claim
that existing rename/lookup paths already enforce the new contract.
