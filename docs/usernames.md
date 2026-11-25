# Usernames

Local usernames are case-insensitive and displayed in lowercase. New account,
import, and rename writes store lowercase. Existing mixed-case rows remain
readable: public/account projections normalize them and name claims already
resolve without regard to case. Reading an old row does not rename it or alter
its aliases. External providers' separate display names are unchanged.

Usernames, aliases and reserved names are unique per tenant: apps that share a
tenant share one namespace, and every rule below (blocking, forwarding,
reservation) applies within that tenant only.

A username is 4 to 30 characters, 64 (hyphens allowed) for a host import. Configure an app-owned list for automatic usernames:

```go
Usernames: []string{"naruto", "sakura", "kakashi"},
```

The YAML field is `usernames`. Each entry is an ASCII letter, then ASCII letters, digits and underscores, 1 to 27 characters, so a generated name fits. Empty, malformed, and case-insensitive duplicate entries are rejected at startup. Nil uses `user`; an explicit empty list is invalid.

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

One fixed policy applies, exported for hosts as `github.com/open-rails/authkit/naming` (tenant names share its former-name reservation):

- A user renames at most once per `naming.RenameCooldown` (72 hours).
- A name its owner renamed away from forwards to the owner and blocks other claims for `naming.FormerNameReservation` (90 days).
- A deleted account keeps its name through the 30-day recovery window. When the account is purged, the name resolves to no one and blocks every claim, forever. The account's former names keep their own expiry.

A reused name belongs to a new account; nothing tied to the old account's ID moves with it. `GET /capabilities` (`username.former_names`) and the account profile (`naming.policy`) report the policy.
