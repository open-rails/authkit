# Usernames

Local usernames are case-insensitive and displayed in lowercase. New account,
import, and rename writes store lowercase. Existing mixed-case rows remain
readable: public/account projections normalize them and name claims already
resolve without regard to case. Reading an old row does not rename it or alter
its aliases. External providers' separate display names are unchanged.

Configure an app-owned list for automatic usernames:

```go
Username: authkit.UsernameConfig{
    RandomNames: []string{"naruto", "sakura", "kakashi"},
    Renames: true,
},
```

The YAML field is `username.random_names`. Each literal base must begin with
an ASCII letter and contain only ASCII letters, digits, and underscores. Its
length plus three must fit the configured username length bounds. Empty,
malformed, and case-insensitive duplicate entries are rejected at startup.
Nil retains a neutral `user` default (fitted to the length bounds); an explicit
empty list is invalid. A maximum length below four still supports manual names
but cannot generate a name with a three-digit suffix.

`Client.GenerateUsername(ctx)` and `GET /usernames/generate` choose a base and
exactly three decimal digits with cryptographic randomness. For example,
`naruto007`. They validate availability and name admission, retry collisions,
and return an error if the bounded search cannot find a name. They do not
reserve it. Automatic passwordless, provider, wallet, and system account
creation retry a database username collision with a fresh generated candidate;
user-chosen registration and rename conflicts are reported without replacing
the user's choice. No automatic name is derived from an email, phone number,
provider username, or display name.

`GET /usernames/availability?username=...` validates syntax before checking
claims, and returns the same unavailable answer for current names, aliases,
and purged accounts' reserved names. These public endpoints share the registration
availability rate limit. Registration availability additionally checks whether
new registration is enabled; the username-only check supports renames on a
site whose registration is closed. Neither says whether an email address or
phone number has an account.

The browser SDK exposes `generateUsername`, `checkUsername`, and
`validateUsername(value, capabilities.username)`. Client syntax checks are
immediate feedback; the server remains authoritative. A successful availability
check is not a guarantee against a concurrent claim before submission.

## Former and deleted names

`Username.FormerNames` and `Username.DeletedNames` (YAML `former_names`,
`deleted_names`) are each an `authkit.NameRetention`: `finite` for `Duration`
(90 days when unset), `forever`, or `immediate`.

- A name its owner renamed away from forwards to the owner and blocks other
  claims. Default: finite, 90 days.
- A deleted account keeps its name through the 30-day recovery window. When
  the account is purged, the name resolves to no one and blocks every claim.
  Default: forever. `finite` frees it after the duration, `immediate` at the
  purge. The account's former names keep their own expiry.

```go
Username: authkit.UsernameConfig{
    DeletedNames: authkit.NameRetention{Mode: authkit.NameRetentionFinite, Duration: 365 * 24 * time.Hour},
},
```

The expiry is fixed when the name is let go: a later policy applies only to
later renames and purges. A reused name belongs to a new account; nothing tied
to the old account's ID moves with it. `GET /capabilities`
(`username.former_names`) and the account profile (`naming.policy`) report
both policies.
