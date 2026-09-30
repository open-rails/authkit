# Stability

AuthKit has two contracts, versioned apart:

- **The Go module** `github.com/open-rails/authkit`, by semantic version. v1 starts at v1.0.2; v1.0.0 and v1.0.1 are retracted.
- **The HTTP API**, by its path version, `/api/v1/`. A breaking change would mount `/api/v2/` beside it.

In v1.x, everything this page covers changes only additively; the rest waits for v2. A security fix may change behavior when that behavior was the vulnerability.

## Go module

The covered API is every exported identifier of the packages below, with its documented behavior. [`api/go.txt`](../api/go.txt) lists it, one line per constant, variable, function, type, struct field (with its tag) and method. `TestGoAPISurface` fails when the packages and the list differ; `go generate ./internal/httpapi` rewrites the list, and the diff is reviewed like code.

| Package | Holds |
|---|---|
| `authkit` | `Migrate`, `New`, `*Client`, `Config` and `Deps` with their sub-configs, the role builder, the `Option`s |
| `iam` | the shared types: actors, refs, typed RBAC names, domain and wire types, events, `Error` and the `Err*` sentinels |
| `verify` | token verification without a database, `Claims`, the middleware |
| `keys` | signing keys: `Source`, `Signer`, `Watch`, JWK and JWKS |
| `provider` | social sign-in providers |
| `devicekey` | the device-key client and its signing domains |
| `adapters/gin`, `adapters/fiber` | mounting on Gin or Fiber, and the middleware |
| `adapters/twilio` | the email and SMS senders |
| `authtest` | test helpers for hosts |

`internal/…`, `cmd/…` and `examples/…` are not covered. Some internal types are re-exported by alias (`authkit.Config`, `authkit.Deps`, `verify.IssuerKeyStatus`, …): the aliases and their members are covered, and `TestGoAPISurface` fails when the covered API reaches an internal type any other way.

Allowed in v1.x:

- new packages, and new exported identifiers in covered ones;
- new struct fields whose zero value keeps the old behavior (write keyed struct literals);
- new `Option`s, enum values (`iam.EventKind`, `iam.MessageKind`, …) and `Err*` sentinels;
- new methods on interfaces only AuthKit implements (`iam.Error`, `provider.Provider`).

Breaking:

- removing or renaming anything in `api/go.txt`, or changing a signature, a field's type or tag, or a constant's value;
- adding a method to an interface a host implements: `EmailSender`, `SMSSender`, `keys.Source`, `keys.Signer`, `provider.Secret`, the `verify` interfaces, the adapters' `Surface`;
- changing documented behavior;
- moving to a new major version of a module whose types the API exposes: pgx v5, go-redis v9, Gin, Fiber v3, `github.com/open-rails/helpers`.

## HTTP API

[`api/openapi.json`](../api/openapi.json) is the contract: every route's method, path, auth tier and permission, its request and response schemas and success statuses, and the error codes with their statuses and typed `metadata` (`x-authkit-error-codes`). It is generated from the route catalog, and CI fails when it is stale. These conventions hold on every route, and the route-catalog tests enforce them:

- **Paths.** The JSON API is `{BasePath}{APIPath}/v1/…`, `/api/v1/…` by default: `APIPath` is the host's prefix, and AuthKit owns the version segment. Browser OIDC (`/oidc/{provider}/…`) and JWKS (`/.well-known/jwks.json`) are unversioned protocol paths. A group is `/groups/{group_id}`, with `root` for the site.
- **JSON.** snake_case members and lower snake_case enum values. Ids are opaque strings: a resource's own is `id`, a reference is `<thing>_id`. Roles and permissions are qualified text (`channel:moderator`, `channel:posts:edit`).
- **Values.** Times are RFC 3339 in UTC. Durations are integer `*_seconds`; `TokenSet.expires_in` follows OAuth 2.0. Every documented member is always present: `null` when unset, `[]` when empty. Clients ignore members and enum values they don't know.
- **Requests.** A body is `application/json` (415 otherwise) of at most 1 MiB, and unknown members are refused (400). GET and DELETE take no body.
- **Statuses.** 200 is a result, 201 a creation (with any secret, shown only then), 202 accepted and 204 done, both without a body. DELETE is idempotent. Sign-in answers 200 with an `AuthResult` whose `status` names the next step.
- **Lists.** `{data, next_cursor}`, paged by `?cursor=&limit=`: the limit is 1–500, 50 by default, and cursors are opaque.
- **Errors.** `{error: {type, code, message, param, metadata}}`. The `code` is stable; the `message` is not contract. Every 5xx is `internal_error`, and 429 is `rate_limited` with `Retry-After`.
- **Credentials.** `Authorization: Bearer` carries a JWT or an API key (`<prefix>_st_<lookup id>_<secret>`), and `DPoP` a sender-bound delegated token's proof. The refresh cookie is `__Host-authkit_rt` (`authkit_rt` over plain HTTP); cookie mounts refuse cross-site requests with 403 `origin_not_allowed`.

Allowed in v1.x: new routes, optional request members, response members, error codes and enum values, and new kinds in `/groups/{group_id}/members/{kind}/{id}` (only `users` today). Breaking: removing or renaming a route, member, code or value; making a request member required; changing a type, status or meaning.

## Tokens

Other services verify AuthKit's JWTs, so these are covered: each token's `typ` header, its claim names and meanings, the signature algorithms (RS256, ES256, ES384, ES512, EdDSA), and JWKS at the issuer plus `/.well-known/jwks.json`.

| `typ` | Minted by | Claims |
|---|---|---|
| `access+jwt` | AuthKit, for a user | `iss sub aud iat exp`; `sid` or `device_key_id`; `jti auth_time amr acr mfa_enrolled`; `provider` after an identity-provider sign-in; `root_role` (display only); `entitlements`; `2fa_enrollment` on an enrollment-only token; the host's claims (`iam.AccessTokenOptions.Claims`), which may not reuse a name on this page |
| `delegated-access+jwt` | AuthKit, or a remote application | `iss aud iat nbf exp jti delegated_sub permissions attributes`; `cnf` (`x5t#S256` or `jkt`) when sender-bound; `sid` or `device_key_id` when AuthKit minted it from a sign-in |
| `remote-application-access+jwt` | a remote application, as itself | `iss aud iat exp`, and `permissions` to narrow its grants; never `sub` |
| `service+jwt` | `Client.MintServiceJWT` | `iss sub aud iat nbf exp jti permissions`, and `token_use` `"service"` |

New claims may be added, so verifiers ignore claims they don't know; `verify` also reads `email`, `email_verified` and `username` when an issuer sets them. Refresh tokens and API-key secrets are opaque.

## Configuration and files

- `Config` and `Deps` are Go values without serialization tags, and AuthKit reads no config file or environment variable. Their field names, types and documented defaults are part of the Go API.
- Rate-limit bucket names, the keys of `HTTPConfig.RateLimits` and `DefaultRateLimits()`, are covered. Their default values are not.
- The bootstrap manifest's YAML and JSON keys (`iam.BootstrapManifest`, `ParseBootstrapManifestYAML`) are covered. An unknown key is a warning, never an error.
- The key directory, `KeysConfig.Path`, holds `keys.json` (`active_key_id`, `active_private_key_pem`, `public_keys`) and `totp.key`. Both formats are covered; see [keys](keys.md).

## Database

AuthKit owns its schema (`Config.Schema`), and only `Migrate` changes it. A v1.x `Migrate` upgrades a database of any earlier v1 release.

One thing in the schema is contract: host tables may reference `<schema>.users(id)` with a foreign key, `ON DELETE CASCADE` or `SET NULL`. The row outlives the account's recovery window and goes when AuthKit purges the account (30 days after deletion, or `Client.PurgeUsers`), once every `Deps.OnPurge` has succeeded. Every other table, column, index and function is private: don't read, write or reference it.

## Events and hooks

- `Deps.OnEvent` receives `iam.Event`. The kinds, the members and the delivery guarantees in `OnEvent`'s doc (recorded with the change, delivered after commit at least once, in order per subject, idempotent on `Event.ID`) are covered. New kinds and members may be added; ignore kinds you don't know.
- The other hooks in `Deps` (`OnPurge`, `NameAdmission`, `DelegatedAuthorization`, `Entitlements`, `EntitlementHolders`, `ClientIP`, `Wrap`) and the senders keep their signatures and documented call semantics. Senders may receive new `iam.MessageKind` values.

## Roles

[RBAC](rbac.md) describes the model and what happens when a host changes its role catalog. The model and the built-in permissions listed there are covered; new built-in permissions may be added.

## auth-ui

`@openrails/auth-ui` is attached to each release as `openrails-auth-ui-<version>.tgz`, at the release's version: pair it with the AuthKit of the same version. Its generated wire types and route table follow the HTTP contract. Its components, hooks and styles are not covered, so pin the exact version.

## Not covered

- `internal/…`, `cmd/…` and `examples/…`.
- Log lines, error `message` text, default rate-limit values, and the order of `Client.Routes()`.
