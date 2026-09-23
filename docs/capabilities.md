# Authentication discovery

`GET {api}/capabilities` exposes `external_login_providers`, a sorted array of configured external login provider summaries. It includes both OIDC providers such as Google and OAuth2 providers such as Discord; each retains its existing ID, display name and login/registration/link flags. There is no legacy `providers` response field.

## Password policy

`embedded.Config.Password` (`password.Policy`) is enforced by every password write: registration, reset, change, fresh-auth set, admin set and bootstrap plaintext. The zero value is the default, following NIST SP 800-63B: 8..128 characters (Unicode code points, ceiling 1024), no composition rules, and the embedded common-password blocklist (about 550k breach-frequency entries from SecLists, case-insensitive; regenerate with `go generate ./password`). A password may never contain the account's username or email local-part when that identifier has at least 4 characters. Hosts may opt into `RequireUppercase`, `RequireLowercase`, `RequireDigit` and `RequireSymbol` (a symbol is any rune that is neither a Unicode letter nor digit, including spaces) and may set `AllowCommon` to disable the blocklist.

```json
"password": {"login": true, "min_length": 8, "max_length": 128, "require_uppercase": false,
             "require_lowercase": false, "require_digit": false, "require_symbol": false, "reject_common": true}
```

Failures are 400 with `param: "password"`: `password_too_short` / `password_too_long` (`metadata: {min_length, max_length}`), `password_requirements_unmet` (`metadata: {missing: ["uppercase"|"lowercase"|"digit"|"symbol", ...]}`), `password_contains_identifier` and `password_too_common`. The blocklist is not published.

## Username policy

`embedded.Config.Username` (`authkit.UsernamePolicy{MinLength, MaxLength}`, default 4..30, ceiling 64) bounds interactive usernames and every derived username (OIDC, passwordless, Solana). The character rule is fixed: `authkit.UsernamePattern`, usable as a JavaScript `u`/`v` regular expression or HTML `pattern`. Operator imports keep the configured minimum, allow hyphens, and accept up to 64 characters.

```json
"username": {"min_length": 4, "max_length": 30, "pattern": "^[A-Za-z][A-Za-z0-9_]*$"}
```

`username_too_short` / `username_too_long` carry `metadata: {min_length, max_length}`; other failures are `username_must_start_with_letter`, `username_cannot_contain_at` and `username_invalid_characters`, all with `param: "username"`.

## Memberships

`GET {api}/me/groups` is always available to an authenticated local user, including deployments that declare only the intrinsic root persona. It returns the caller's current actual assignments with `group_id`, `persona`, `instance_slug` and `role`. A user with no assignments receives `{"object":"list","data":[]}`. It neither implies root membership for every user nor allows selecting another user's identity in query parameters. Group management routes still follow their configured persona capabilities.
