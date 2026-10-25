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
and reserved former names. These public endpoints share the registration
availability rate limit. Registration availability additionally checks whether
new registration is enabled; the username-only check supports renames on a
site whose registration is closed. Neither says whether an email address or
phone number has an account.

The browser SDK exposes `generateUsername`, `checkUsername`, and
`validateUsername(value, capabilities.username)`. Client syntax checks are
immediate feedback; the server remains authoritative. A successful availability
check is not a guarantee against a concurrent claim before submission.
