# Tokens

This page covers the credentials AuthKit issues, how long each lasts, and when a revocation takes effect. Which subject each credential acts as, and who invokes it, is in [Subject, Invoker, Credential](identity.md). Each JWT's `typ` and claims are listed in [Stability](stability.md#tokens), and the middleware godoc in `verify` describes the gates.

## Credentials

| Credential | Who holds it | Lifetime | Revocation |
|---|---|---|---|
| Access token (`access+jwt`) | a signed-in user | `TokenConfig.AccessTokenDuration`, 15 minutes by default | live gates refuse it at once; `Required` accepts it until it expires |
| DPoP-bound session | a client that proved a key at sign-in (`SignIn.DPoP`, [resource server](resource-server.md#dpop)) | as its session | its access tokens carry `cnf.jkt` and need a proof of the key; each refresh proves it |
| Refresh token | a signed-in user | until revoked, or for `TokenConfig.RefreshTokenDuration` | at once |
| Device-key sign-in | a native client | each sign-in is signed by the device key, with no refresh token | like a session, when the key is revoked |
| API key | a group's account | until revoked or its expiry (capped by `APIKeysConfig.MaxTTL`) | at once, since it is resolved on every request; also when its creator loses the authority to issue it |
| Resource access token (`at+jwt`) | an OAuth client, for a resource server | `AuthorizationServerConfig.AccessTokenTTL` (5 minutes) | at expiry; each grant re-checks the session it stands on ([authorization server](authorization-server.md)) |
| Workload token (`at+jwt`, jwt-bearer) | a workload, for a resource server | until its capability expires (at most 24 hours) | at once for a resource server that checks its device key (`verify.RequireSession`); revoking the device key revokes it ([workloads](authorization-server.md#workloads)) |

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
  - `Client.Can`, and every operation that takes an identity;
  - every AuthKit route that changes state, except sign-out.

  A revoked session's token fails there at once, with 401 `session_revoked`. A stale sign-in at `Sensitive` (or an AuthKit route that needs a recent one) is 401 `step_up_required` with RFC 9470's challenge, `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="900"`.
- `verify.Required` is stateless. It accepts a token until it expires, which can be up to 15 minutes after sign-out. Use it only where that is acceptable.
- Code behind a gate that wants a helpers/auth `Verified` request calls `verify.AuthenticateRequest`, which reuses the gate's verification, since a DPoP proof is single-use. `verify.AuthenticateSession` adds the session check; unlike `RequireSession`, it passes a credential with no sign-in, such as an API key. Over an `*authkit.Client` it also implements helpers/auth `RecentSignInChecker`: `CheckRecentSignIn` is `Sensitive`'s check, for code that moves money or grants access, and a stale sign-in is a `*auth.Challenge`: `auth.ErrStepUpRequired`, its `MaxAge` and the `step_up_required` metadata. `Client.Authenticator()` is the same, for a library that guards its own routes.
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

## Remote applications

A remote application registers another issuer a resource server may trust: `Client.RemoteApplication` by issuer gives its keys (or JWKS URI) and, as `Permissions`, the ceiling its role in its group confers. With `Config.Resource`, AuthKit's own `Client.Authenticator()` admits its tokens for the resource ([resource server](resource-server.md)); AuthKit's own API never does.

`Config.RemoteApplications` declares root's remote applications as a whole set. `New` registers each one, and disables any that an earlier boot declared and this one doesn't. A removed application is disabled, not deleted: resource servers read it as disabled at once, and it keeps its roles for when it is declared again. `nil` leaves the stored applications alone, and applications registered through `Client.UpsertRemoteApplication` or the bootstrap manifest are never touched.

`Client.DeclareRemoteApplications(ctx, group, apps)` is the same declared set for one group that exists after `New` (a host's merchant, say). Each application is registered in that group with its declared `Role` there, the ceiling of what its tokens may do in the group (none when zero). A later call disables what it no longer lists, in that group only; root's `Config.RemoteApplications` and other groups' sets are left alone.
