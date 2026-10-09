# Tokens

This page covers the credentials AuthKit issues, how long each lasts, and when a revocation takes effect. Each JWT's `typ` and claims are listed in [Stability](stability.md#tokens), and the middleware godoc in `verify` describes the gates.

## Credentials

| Credential | Who holds it | Lifetime | Revocation |
|---|---|---|---|
| Access token (`access+jwt`) | a signed-in user | `TokenConfig.AccessTokenDuration`, 15 minutes by default | live gates refuse it at once; `Required` accepts it until it expires |
| Refresh token | a signed-in user | until revoked, or for `TokenConfig.RefreshTokenDuration` | at once |
| Device-key sign-in | a native client | each sign-in is signed by the device key, with no refresh token | like a session, when the key is revoked |
| API key | a group's machine client | until revoked or its expiry (capped by `APIKeysConfig.MaxTTL`) | at once, since it is resolved on every request; also when its creator loses the authority to issue it |
| Delegated token (`delegated-access+jwt`) | a service acting for a user or an outside actor | `DelegatedConfig.TTLDefault` (15 minutes), at most `TTLCeiling` (1 hour) | when the user's sign-in ends, if AuthKit minted it from one; when its application is disabled, if an application did |
| Remote-application token | a remote application | set by the application | when the application is disabled or deleted |
| Service JWT (`service+jwt`) | your own services | at most 15 minutes by default (`verify.WithServiceJWTMaxLifetime`) | at expiry only; it grants no AuthKit authority |
| Resource access token (`at+jwt`) | an OAuth client, for a resource server | `AuthorizationServerConfig.AccessTokenTTL`, at most 5 minutes | at expiry; each grant re-checks the sign-in it stands on ([authorization server](authorization-server.md)) |

## Refresh and sessions

- Each sign-in opens a session and returns a refresh token: in the body, or in the `__Host-authkit_rt` cookie with `HTTPConfig.RefreshCookie`.
- `POST /api/v1/token` rotates it: each use returns a new refresh token and retires the old one.
- Presenting a token retired within the last 90 days ends the session, since it means the token was copied; an older one is refused. For 30 seconds after a rotation (`TokenConfig.RefreshRotationGrace`), the retired token instead gets the same successor again, which covers two holders refreshing at once.
- A user keeps at most 3 sessions (`TokenConfig.SessionMaxPerUser`); the oldest is evicted.
- These end sessions:
  - signing out ends that session;
  - `DELETE /api/v1/me/sessions` ends every other session;
  - a password change ends every other session;
  - a ban, deletion, or `Client.RevokeAccountSessions` ends all of them.
- Account-level revocations reach every issuer in `TokenConfig.AccountIssuers`.

## Revocation timing

An access token is a signed JWT, so it outlives its session unless something checks the session:

- The live gates check the session on every request:
  - `verify.RequireSession`, `RequirePermission` and `Sensitive`, and their Gin and Fiber versions;
  - `Client.Can`, and every operation that takes an actor;
  - every AuthKit route that changes state, except sign-out.

  A revoked session's token fails there at once, with 401 `session_revoked`.
- `verify.Required` is stateless. It accepts a token until it expires, which can be up to 15 minutes after sign-out. Use it only where that is acceptable.
- Code behind a gate that wants a helpers/auth principal calls `verify.AuthenticateRequest`, which reuses the gate's verification, since a DPoP proof is single-use. `verify.AuthenticateSession` adds the session check; unlike `RequireSession`, it passes a credential with no sign-in, such as an API key. Over an `*authkit.Client` the principal also implements helpers/auth `RecentSignInChecker`: `CheckRecentSignIn` is `Sensitive`'s check, for code that moves money or grants access, and a stale sign-in is `auth.ErrStepUpRequired` carrying the `step_up_required` metadata.
- Roles are read live at every permission check. The `root_role` and `entitlements` claims are snapshots taken at mint: fine for display or content tiers, never for authorization.

## Verifying AuthKit tokens in another service

A service without AuthKit's database registers the issuer on a `verify.Verifier`:

```go
v := verify.NewVerifier()
if err := v.AddIssuer("https://myapp.com", []string{"myapp"}, verify.IssuerOptions{
	JWKSURI: "https://myapp.com/.well-known/jwks.json",
	IsLocal: true, // its users are this service's users: Claims.UserID is set
}); err != nil {
	return err
}
mux.Handle("/api/", verify.Required(v)(api))
```

- The verifier caches JWKS keys for `IssuerOptions.CacheTTL` (10 minutes), and refetches when a token names an unknown `kid`, so key rotations need no restart ([keys](keys.md)).
- While fetches fail, the cached keys keep verifying for up to `MaxStale` (4 hours). After that, the issuer's tokens fail with 503 `issuer_keys_unavailable`. `CheckIssuerKeys` reports this state for health probes.
- Such a verifier can't check sessions or permissions, so only `Required` and `Optional` work with it. A service on the same database gets the live gates from `Client.NewVerifier(audiences)`.

## Delegated tokens

Deprecated: `POST /api/v1/delegated/token` and delegated tokens remain in v1 and are removed in v2. New integrations use the [authorization server](authorization-server.md): token exchange for a frontend, client credentials for a machine.

- AuthKit mints delegated tokens in two ways:
  - at `POST /api/v1/delegated/token`, for one of `DelegatedConfig.Audiences`, with `Deps.DelegatedAuthorization` deciding the grant;
  - through `Client.MintDelegatedAccessToken`.

  A remote application may also sign its own.
- `Config.RemoteApplications` declares root's remote applications as a whole set. `New` registers each one, and disables any that an earlier boot declared and this one doesn't. A removed application is disabled, not deleted: its tokens stop at the next request, and it keeps its roles for when it is declared again. `nil` leaves the stored applications alone, and applications registered through `Client.UpsertRemoteApplication` or the bootstrap manifest are never touched.
- A delegated token's authority is its `permissions` claim, capped by the application's stored grants when an application signed it. The user's roles don't apply.
- A token can be bound to its holder:
  - `cnf.x5t#S256` binds it to a TLS client certificate;
  - `cnf.jkt` binds it to a DPoP key (`DelegatedConfig.AllowDPoP`).

  A bound token needs its proof on every request. `Client.NewVerifier` wires DPoP itself; a standalone verifier needs `verify.WithDPoP` and `verify.WithPublicURL`.
