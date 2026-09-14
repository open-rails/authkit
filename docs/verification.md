# Verification trust and key ownership

`authhttp.New` registers the engine's issuer as local and reads its live public
keys on every verification. `Claims.UserID`, `Claims.IsUser()`, Gin `UserClaims`,
and AuthKit account/permission lookups are reserved for that local namespace.
Standalone verifiers use `IssuerOptions.IsLocal` only when the configured signer
is authoritative for their local user IDs.

The unused `IssuerOptions.RemoteApplicationSlug` option has been removed;
application identity is always resolved from the store.

Explicit `AddIssuer` registrations otherwise trust an external issuer. An
external `access+jwt` yields `Claims.Subject` and `Claims.Issuer`, with an empty
`UserID`. Use `Claims.Principal()` for the qualified identity. Map that pair to
a local account deliberately before looking up local permissions. Registering
an application in the store never grants authority over local users.

Applications loaded by `LoadRemoteApplications` or discovered through
`WithService` / `SetRemoteApplicationSource` are store-managed. Every token and
document verification reads the current enabled application row; deletion,
disablement or a lookup failure rejects. Static keys and trust-mode changes
apply on the next verification on every replica. Application self and delegated
tokens additionally require the live authority resolver. Delegation inherits
the application's permission ceiling and immutable group binding, including
when no permissions are claimed. It cannot become unbound by changing `typ`. Specialized delegated results also
carry this boundary in `DelegatedPrincipal.PermissionGroup`; only explicit
platform delegation has a nil scope. Consumers must compare the target group
and authority issuer against this scope; accepting `Permissions` alone drops
the restriction. Prefer `verify.Allow` / `RequirePermission` with the returned
`Claims` and a resolved target scope.
Do not manually `AddIssuer` a store-managed application: that declares explicit
host trust instead of store ownership. Store registration cannot overwrite an
explicitly configured issuer; resolve conflicting configuration deliberately.

Explicit platform delegation configured with `AddIssuer` remains stateless and
unbound. The receiving host owns resource authorization. `WithPermissions` adds
catalog validation to every typed delegated verification path; it cannot replace
resource authorization. `Verify`, `VerifyRequest`, and both
`VerifyDelegatedAccess` variants share issuer and authority policy. A certificate
binding requires the request variant with the matching TLS peer certificate.
`VerifyClaims` is the low-level custom-profile API: it verifies keys, live issuer
eligibility and registered claims, but leaves token type, subject, permission
and sender-proof rules to the caller.

Key sources have distinct owners:

- `Keys` and `RawKeys` are snapshots, replaced by `AddIssuer`. A successful empty
  replacement removes all previous keys. Invalid replacements return an error
  and preserve the complete previous registration, including audiences.
- `PublicKeys` is a live in-process callback; callers provide a safe snapshot
  on each call. It cannot be combined with another source. Removed local keys
  stop verifying immediately; retain retired keys in the source for any intended
  overlap. Neither live nor static sources synthesize network requests.
- `JWKSURI` is fetched and cached for `CacheTTL` (default 10 minutes). A failed
  refresh can reuse cached keys for `MaxStale` beyond that TTL (default 1 hour).
  These settings also apply to any initial supplied keys. Unknown KIDs and
  signature failures trigger a throttled refresh. External JWKS revocation is
  therefore bounded by cache TTL plus allowed staleness, not instantaneous.

PEM, JWK, raw public keys and built-in signing keys use the same supported-key
policy: RSA 2048–8192 bits, P-256/P-384/P-521, or Ed25519. Invalid key sets cannot
silently leave an earlier registration active while reporting successful rotation.
