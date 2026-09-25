# Verification trust and key ownership

`embedded.New` with `Config.HTTP` registers the engine's issuer as local and reads its live public
keys on every verification. `Claims.UserID`, `Claims.IsUser()`, Gin `UserClaims`,
and AuthKit account/permission lookups are reserved for that local namespace.
Standalone verifiers use `IssuerOptions.IsLocal` only when the configured signer
is authoritative for their local user IDs.

## User claims: presence and freshness

`verify.UserClaimsData` is the shared local-user projection. Read it with
`verify.UserClaimsFromContext(ctx)` after authentication middleware. A successful
result guarantees a nonempty local `UserID`; it does not guarantee the other
fields are populated. The accessor performs no verification or database lookup
and copies the `AMR` and `Entitlements` slices.

| Fields | Ordinary `Required` / `Optional` | `RequiredLive` |
| --- | --- | --- |
| `UserID` | Verified local user ID | Same ID, plus live account eligibility checked |
| `Email`, `EmailVerified`, `Username` | Only populated if present in verified claims; ordinary AuthKit access tokens omit them | Loaded from the account-liveness lookup for this request |
| `SessionID` | Token's session ID, if supplied | Unchanged; this is not a session-revocation lookup |
| `Entitlements` | Token-time snapshot, if supplied | Unchanged; no live entitlement lookup |
| `AMR`, `ACR`, `AuthTime`, `MFAEnrolled` | Issuer's authentication/enrollment claims, if supplied | Unchanged; no assurance or enrollment refresh |

An empty email/username does not establish that the account lacks that value.
`EmailVerified == false` can mean the claim was absent. Empty session/assurance
values and zero `AuthTime` similarly mean unavailable data. Sessionless
credentials such as device-key tokens need not carry a `SessionID`.

`AMR` describes authentication methods used, `ACR` the issuer's assurance class,
and `AuthTime` when authentication occurred rather than when a token was
refreshed. `MFAEnrolled` is enrollment information at token issuance, not proof
that this authentication performed MFA; use the assurance/step-up checks.

A snapshot can become stale: revoking an entitlement after a token was issued
does not edit that signed token. Signature verification establishes who issued
the claims, not that every claim still matches current database state. Where
immediate changes matter, use the owning service's live authorization lookup.
`RequiredLive` refreshes only the profile fields shown above, and the lookup's
result describes that moment, not a guarantee against later concurrent changes.

## Issuer trust

The unused `IssuerOptions.RemoteApplicationSlug` option has been removed;
application identity is always resolved from the store.

`AddIssuer` requires at least one accepted audience; an issuer without one
would accept its tokens for every audience.

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

Explicit platform delegation configured with `AddIssuer` has no stored group
binding. The receiving host owns resource authorization. `WithPermissions` adds
catalog validation to every typed delegated verification path; it cannot replace
resource authorization. `Verify`, `VerifyRequest`, and both
`VerifyDelegatedAccess` variants share issuer and authority policy. A certificate
binding requires the request variant with the matching TLS peer certificate.
A `cnf.jkt` binding requires `WithDPoP`, the `DPoP` authorization scheme, and a
fresh matching proof. Detached verification rejects either binding. See
[browser delegation](browser-delegation.md) for the receiver replay and URL contract.
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
- `JWKSURI` is fetched and cached for `CacheTTL` (default 10 minutes), which
  also applies to any initial supplied keys. Expired keys keep verifying while
  one background loop per issuer refetches them (3s per attempt, capped jittered
  backoff, until success); requests never wait on it. Only transport errors,
  5xx and 429 keep cached keys: any other answer is authoritative, so its valid
  keys replace the cache (malformed, weak or unsupported keys are skipped) and
  one without usable keys, a 4xx or a non-JSON body drops it. Stale keys are
  trusted for at most `MaxStale` (default 4 hours, never below `CacheTTL`) after
  the last successful fetch, so blocking our fetch cannot keep a revoked key
  valid. An issuer with no usable keys gets one bounded attempt, then
  `503 issuer_keys_unavailable` (expired or wrong-audience tokens still get
  their 401); other issuers are unaffected. Unknown KIDs and signature failures
  trigger a throttled refresh. `Verifier.IssuerKeyStatuses()` reports each JWKS
  issuer (including key `Age` and `Expired`) and `Verifier.CheckIssuerKeys` is
  a no-I/O probe for a dependency supervisor.

PEM, JWK, raw public keys and built-in signing keys use the same supported-key
policy: RSA 2048–8192 bits, P-256/P-384/P-521, or Ed25519. Invalid key sets cannot
silently leave an earlier registration active while reporting successful rotation.
