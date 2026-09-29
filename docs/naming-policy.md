# Username naming

AuthKit identifies users by immutable UUID. A username resolves, as a current
name or a live alias, to one UUID; authorization and the operation keep that
UUID. Permission groups have no names: the app names what a group guards.

## Case

Names are never case-sensitive and never refused for their case. A username
keeps the spelling its owner chose for display (`users.username` is `citext`),
while uniqueness, login, availability, pending-registration holds and alias
resolution use the lowercase key in `name_claims`: `Fidika` and `fidika` are
one account. Renaming to another case of your own name changes only the display
spelling (no claim, alias or cooldown).

## Configuration

`Config.Naming` is an `iam.NamingConfig`. Omitted fields mean renames enabled,
72 hours between successful renames, and former names retained for 2160 hours
(90 × 24 hours, independent of DST).

```go
cfg.Naming = iam.NamingConfig{} // defaults
enabled := false
cfg.Naming = iam.NamingConfig{Enabled: &enabled} // no ordinary renames
interval := time.Duration(0)
cfg.Naming = iam.NamingConfig{ // any frequency, former names released at once
	RenameInterval: &interval,
	FormerNames:    iam.FormerNameRetentionConfig{Mode: iam.FormerNamesImmediate},
}
cfg.Naming = iam.NamingConfig{ // former names reserved forever
	FormerNames: iam.FormerNameRetentionConfig{Mode: iam.FormerNamesForever},
}
```

An empty retention object, or `finite` without a duration, uses 2160h. A
duration without a mode means finite; finite zero normalizes to immediate.
Forever and immediate reject any duration, including zero. Negative values,
unknown modes and overflow fail `New`.

HTTP `naming.policy` carries `enabled`, `former_name_retention_mode` and
`former_name_retention_seconds` (a number, fractional seconds kept). Rename
timing is reported by `next_rename_at`/`retry_after_seconds` and the action's
`cooldown_seconds`.

## Runtime contract

The first rename has no delay. A successful rename at T permits another at
T+interval. Failed attempts and no-ops do not advance the timestamp. The
cooldown belongs to the identity, not its session. There is no force-rename,
and an import never renames an existing account.

Aliases point to UUIDs and report the owner's current name. A finite alias
resolves and blocks other owners only while `now < expires_at`; then it stops
resolving and becomes claimable, checked on every lookup and claim. Renaming
back to an owned alias follows the same policy. Policy changes affect future
aliases, not issued ones. Disabling renames does not disable forwarding.

Deletion does not forward to a dead identity or free its reservations early. A
purged user's username stays reserved forever.
Writes resolve aliases internally; there are no redirects. Credentials and jobs
are UUID-bound.

## Storage

`name_claims` owns each normalized username, with the owner UUID,
canonical/alias state and alias deadline. One canonical name per owner. Creation claims the name and inserts the identity in one statement;
triggers refuse direct name or UUID changes outside an atomic transition.
Renames lock the owner, re-read its name, then change claims and identity in one
transaction. Namespace locks use 256 ordered stripes. Resolver reads are
uncached. The auth-state cleanup (`Config.River.CleanupInterval`) deletes at
most 5000 expired aliases per run; it never decides forwarding or claims.

## API

- `User(ctx, iam.UserByUsername(name))` resolves live aliases to the owner;
  `ResolveUsername(ctx, name)` also says whether `name` is an alias and until
  when. Deleted and purged owners resolve nobody.
- `CheckUsername(ctx, name)` is availability for a new account: the username
  policy's error, `username_in_use` for any claim (current, live alias,
  purged account, pending registration; identical whoever holds it), then
  `Deps.NameAdmission`. It is Go-only; rate-limit it before serving it.
- `Deps.NameAdmission` is the host's side-effect-free username policy
  (`iam.NameAdmissionRequest`), run on account creation and rename.
- `Deps.Clock` supplies naming timestamps.
