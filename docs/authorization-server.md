# Authorization server

With `Config.AuthorizationServer`, a deployment is an OAuth 2.0 authorization server and OpenID provider: registered clients sign its users in ("Sign in with MyApp") and get access tokens for registered resource servers, which authorize from the token alone.

```go
cfg.AuthorizationServer = authkit.AuthorizationServerConfig{
	Resources: []authkit.ResourceServerConfig{{
		ID:          "https://billing.example.com", // the access token's aud
		Scopes:      []string{"billing:merchant"},
		Permissions: []string{"merchant:*"}, // the resource's ceiling
	}},
	Clients: []authkit.OAuthClientConfig{{
		ID:           "billing-console", // a public browser client
		Name:         "Billing",
		RedirectURIs: []string{"https://billing.example.com/callback"},
		Resources:    []string{"https://billing.example.com"},
		GrantTypes:   []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken},
	}, {
		ID:         "admin-ui", // the host's own frontend
		Origins:    []string{"https://admin.example.com"},
		Resources:  []string{"https://billing.example.com"},
		GrantTypes: []authkit.OAuthGrantType{authkit.GrantTokenExchange},
	}, {
		ID:           "payout-worker", // a machine
		SecretSHA256: workerSecretSHA256,
		Resources:    []string{"https://billing.example.com"},
		Permissions:  []string{"merchant:payouts:read"},
		GrantTypes:   []authkit.OAuthGrantType{authkit.GrantClientCredentials},
	}},
}
```

- Declared clients are first-party: sign-in needs no consent screen. Groups also register their own, third-party clients at run time ([group clients](#group-clients)).
- A confidential client sets `SecretSHA256`, the hex SHA-256 of a secret of at least 32 random bytes; AuthKit never holds the secret. A public client chooses DPoP (RFC 9449): a proof at the token endpoint binds its tokens, and without one its refresh tokens rotate (RFC 9700 §4.14.2). `SignIn.DPoP` required refuses a user grant (code, refresh, token exchange) without a proof; client credentials are never covered. Every workload jwt-bearer request proves its key.
- Redirect URIs match exactly: https, or http on a loopback host.

## Group clients

A group of a persona declared with `authkit.OAuthClients` registers OAuth clients at run time, such as a merchant's "Sign in with openrails.dev". There is no open registration endpoint: the group's staff manage them under `<persona>:credentials:manage` (reading under `:credentials:read`), with a recent sign-in for changes.

```go
roles := authkit.NewRoles()
roles.Persona("merchant", authkit.OAuthClients)
cfg.AuthorizationServer.Resources = []authkit.ResourceServerConfig{{ID: "https://api.example.com", Scopes: []string{"shop:self"}}}
cfg.AuthorizationServer.GroupClients = authkit.GroupClientsConfig{
	Scopes:     []authkit.GroupClientScope{{Name: "shop:self", Resource: "https://api.example.com", Description: "See and manage your orders here"}},
	Agreements: []string{"network-terms"}, // accepted before approving any group client
}
deps.GroupName = func(ctx context.Context, groupID string) (string, error) { return shops.Name(ctx, groupID) } // the consent screen's name
```

- Metadata follows RFC 7591: `client_name`, `logo_uri`, `client_uri`, `policy_uri`, `tos_uri`, `redirect_uris` (exact, https; http on loopback), `post_logout_redirect_uris`, `token_endpoint_auth_method` (`private_key_jwt` with `jwks_uri`, `client_secret_basic`, or `none` for a public app), `scope` (`openid` and any of `email`, `phone`, `profile` and the `GroupClients.Scopes`) and `backchannel_logout_uri`. Go: `Client.CreateGroupOAuthClient`, `GroupOAuthClients`, `GroupOAuthClient`, `UpdateGroupOAuthClient` (`Disabled` too), `RotateGroupOAuthClientSecret`, `DeleteGroupOAuthClient`; HTTP: `/groups/{group_id}/oauth-clients[/{client_id}]` and `POST .../{client_id}/secret`. A client_secret_basic secret is shown once. A group holds at most 10.
- They use the authorization code grant with PKCE and refresh tokens, nothing else. A `private_key_jwt` client authenticates with an RFC 7523 assertion: `iss` and `sub` its `client_id`, `aud` the issuer or the token endpoint, at most five minutes to live, its `jti` spent once, signed by a key its `jwks_uri` publishes (fetched through the SSRF guard and cached).
- **Consent.** The first authorization of a group client asks the user (OIDC Core §3.1.2.4): approving answers `consent_required` (409) naming the scopes yet to consent to, each with its description (OpenID's own scopes have none: the interface describes them), and `GET /oauth2/authorizations/{id}`'s `third_party` carries the group's name, the client's links and where the browser returns. The SPA shows them and approves with `{"consent": true}`. Consent is remembered; a later request asks only for scopes it adds, and `prompt=consent` asks again. With `prompt=none` the SPA declines with `consent_required`.
- **Claims.** `sub` is the user id, the same for every client (public subject type). `email` releases the email and `phone` the phone number only once proven; `profile` releases nothing (an account holds no name, and a username may spell a phone number). Its tokens carry no `permissions` or `roles`.
- **Bound to the group.** A resource server built on `Client.Authenticator()` (`Config.Resource`) binds the client's tokens to its group (helpers/auth `Bound`): they act there only. Its Verified's `ClientID()` and `Scopes()` name the client and the scopes granted, for routes a scope opens rather than a permission. A client gets an access token for a resource only with one of that resource's `GroupClients.Scopes`. A disabled or deleted client, or one of a deleted group, is refused at its next request, refresh or sign-in.
- **ID tokens in process.** `Client.VerifyIDToken` checks an ID token this server issued, such as one a client hands back to prove a fresh sign-in: signature, issuer, one audience, lifetime, a client still enabled and a sign-in that still stands. `iam.IDToken` names the user, client, owning group, nonce and `auth_time`; the caller compares them with what it expects.
- **Withdrawing consent.** `GET /me/oauth-consents` lists the user's connected apps and `DELETE /me/oauth-consents/{client_id}` disconnects one; `Client.RevokeConsent` does the same for the host. `Deps.ConsentRevocationCheck` may refuse a user's own withdrawal with `iam.RefuseConsentRevocation(reason)`: `consent_revocation_refused` (409, `metadata.reason`); the host's is never asked. The client's refresh tokens for the user stop at their next use, its `backchannel_logout_uri` receives an OIDC Back-Channel Logout token (`logout+jwt`, through River, retried), and `oauth_consent.revoked` is recorded. Events `oauth_client.created`, `.updated` and `.deleted` record the clients' changes.

## Endpoints

Beneath the issuer's path, as the metadata at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`) lists them:

| Endpoint | Does |
|---|---|
| `/oauth2/authorize` | authorization code with PKCE S256 (required), `resource` (RFC 8707), `prompt=none\|login`, `max_age`; the response carries `iss` (RFC 9207) |
| `/oauth2/token` | the grants below; a `DPoP` proof binds the tokens to its key (`token_type` `DPoP`, `cnf.jkt`) |
| `/oauth2/revoke` | RFC 7009: ends a refresh token's family; any token answers 200 |
| `/oauth2/userinfo` | the user's claims, for an access token with the `openid` scope (a DPoP-bound one with its proof) |
| `/oauth2/end_session` | RP-initiated logout: ends the sign-in `id_token_hint` names |

Errors are OAuth's `{error, error_description}`. Until the client and redirect URI check out, the authorize endpoint answers itself; after that it redirects back to the client with the error.

## Signing in

The authorize endpoint stores the request and sends the browser to the SPA at `Frontend.AuthorizePath` (`/authorize`) with `?authorization=<id>`. The SPA:

1. reads the request: `GET {api}/oauth2/authorizations/{id}` (the client's name, scopes, `prompt`, `max_age`);
2. signs the user in as usual, second factors included;
3. approves it with that session (a device-key sign-in cannot): `POST {api}/oauth2/authorizations/{id}/approve` answers `{redirect_to}`, the client's redirect URI with a one-time code. A request asking for a fresher sign-in than the user's (`prompt=login`, `max_age`) answers 401 `step_up_required`; step up and approve again.

auth-ui's `OAuthAuthorize` component is that page.

For `prompt=none` with nobody signed in, or when the user refuses, the SPA declines: `POST {api}/oauth2/authorizations/{id}/decline` with `{"error": "login_required"}` (or `access_denied`, `interaction_required`).

## Grants

| Grant | For | Answer |
|---|---|---|
| `authorization_code` | a browser or server client signing the user in, with PKCE; `dpop_jkt` on the authorize request binds the code to the key | access token, ID token with `openid`, refresh token with `refresh_token` |
| `refresh_token` | the same client, proving the same DPoP key; `scope` may narrow | rotated tokens with live permissions |
| `urn:ietf:params:oauth:grant-type:token-exchange` | a host frontend (RFC 8693): `subject_token` is the user's AuthKit session access token, `subject_token_type` `urn:ietf:params:oauth:token-type:access_token` | an access token for `resource`, on the same session; impersonation (RFC 8693 §1.1), so no `act` |
| `client_credentials` | a confidential client acting for itself | an access token with `sub` = `client_id` and the client's `Permissions` within the ceiling |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | a [workload](#workloads) acting for a user (RFC 7523): `assertion` signed by its key, carrying the capability the user's device key signed, with a DPoP proof of the same key | an access token for the user, `act` the workload, bound to its key, carrying the capability's operations until it expires; no refresh token |

Refresh tokens rotate on every use. A family stands on the session it was issued from and lasts `RefreshTokenTTL` (12 hours by default), which rotation never extends; then the client signs in again with `prompt=none`. Presenting a rotated-out token revokes the family, newest token included. `offline_access` is refused.

`authorization_details` (RFC 9396) is granted only by a [workload's capability](#workloads): the authorize and token endpoints refuse the parameter.

## Workloads

A workload (a worker, an agent, a CI runner) acts for a user only through a capability the user's device signs offline: exactly the operations it may do, on one resource, until it expires. There is no round trip to AuthKit for the user, and AuthKit stores nothing per workload.

```go
cfg.DeviceKeys.Enabled = true // device keys sign capabilities
cfg.AuthorizationServer.Clients = append(cfg.AuthorizationServer.Clients, authkit.OAuthClientConfig{
	ID:                        "tensord", // one client per kind of workload; public
	Resources:                 []string{"https://hub.example.com"},
	AuthorizationDetailsTypes: []string{"hub_operation"},
	GrantTypes:                []authkit.OAuthGrantType{authkit.GrantJWTBearer},
})
deps.OAuthGrants = func(ctx context.Context, r iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
	kept, err := hub.OperationsOf(ctx, r.UserID, r.AuthorizationDetails) // the user's own resources only
	if errors.Is(err, errNotTheirs) {
		return iam.OAuthGrantDecision{}, iam.ErrOAuthGrantRefused // invalid_grant, reason refused
	}
	if err != nil {
		return iam.OAuthGrantDecision{}, err // temporarily_unavailable
	}
	return iam.OAuthGrantDecision{AuthorizationDetails: kept}, nil
}
```

1. The user's device (a CLI holding an enrolled [device key](tokens.md)) signs the capability with `devicekey.SignCapability`: a JWT with header `alg` `EdDSA`, `typ` `authkit-capability+jwt` and `kid` the device key's id, and claims `sub` (the user), `aud` (the resource's ID), `cnf.jkt` (the workload key's RFC 7638 thumbprint), `authorization_details` (RFC 9396, of the client's types), `jti`, and `exp` at most 24 hours ahead. Its other claims, such as a run id, reach the host untouched.
2. The workload posts `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `client_id`, `assertion`, and optionally `resource` (the capability's `aud`), with a `DPoP` proof of its P-256 key (no `ath`). The assertion is a JWT signed by that key: header `alg` `ES256` and `jwk` (`kty`, `crv`, `x`, `y` only), `typ` `JWT` if any; claims `iss` the `client_id`, `sub` the workload's name for itself, `aud` the metadata's `token_endpoint` alone, `exp` at most 5 minutes ahead, a `jti` of 16-128 characters, and `capability`, the capability's compact JWT.
3. AuthKit verifies both signatures, that the device key is live and the user's, that the user is usable, and that the capability, the assertion and the DPoP proof name the same workload key. It then asks the grant authorizer (`Deps.OAuthGrants`, which decides only this grant) with `Kind` `jwt_bearer`: `UserID`, `DeviceKeyID`, `Resource`, the capability's `AuthorizationDetails`, `JWKThumbprint` (the workload key), and the verified `Assertion` and `Capability` (their ids, times and other claims). `iam.ErrOAuthGrantRefused` refuses; any other error is an outage (`temporarily_unavailable`). The decision may narrow `AuthorizationDetails` by dropping entries (each kept entry must be one of the capability's); `Invoker` names the workload in `act` (default: its key thumbprint); `MaxLifetime` shortens the token; `Claims` adds access-token claims, each named by an absolute URI.
4. The token is an `at+jwt` with `sub` the user, `act` `{"sub": <Invoker>}`, `cnf.jkt` the workload key, `device_key_id` the capability's key, `authorization_details` as decided, and `permissions` empty; no `scope`, `sid`, `auth_time`, `acr` or `amr`. It lasts until the capability expires (or `MaxLifetime`), not `AccessTokenTTL`, and has no refresh token: one exchange per capability.

Each `jti` redeems once: the assertion's per workload key, the capability's per device key. A spent assertion is kept with spent DPoP proofs (`Deps.Redis`, else memory); a spent capability is a grant record, kept in PostgreSQL. Nothing is spent until the token is minted, so a failed request may be retried with the same capability.

The client may be public: the assertion and the DPoP proof prove the workload key and the user's signature authorizes it, so a secret shared by a fleet would add only a secret to leak. A stolen token is useless without the workload key, and a stolen capability is useless without the key and its unspent `jti`.

Revoking the device key ends every token its capabilities minted, at once, for a resource server in the issuer's process: `verify.RequireSession` over a `Client.NewVerifier` (or `Client.CheckSession` on the claims) checks the token's device key with one query, answering 401 `session_revoked`.

A refusal is `invalid_grant` with a `reason` beside it: `assertion_invalid`, `assertion_replayed`, `capability_invalid`, `capability_expired`, `capability_replayed`, `device_key_revoked` (unknown, revoked, or a ban revoked it), `key_mismatch` (the capability names another workload key), `user_unavailable` or `refused` (the authorizer). Also `invalid_dpop_proof` (no proof, or reason `key_mismatch` for another key's), `invalid_target` (a resource that is not the capability's, or not the client's), `invalid_scope` (any `scope`), `unauthorized_client` and `temporarily_unavailable` (the authorizer failed).

In tests, `authtest.EnrollDeviceKey` enrolls a device key, `DeviceKey.Capability` signs a capability, `AuthorizationServer.JWTBearer` (`JWTBearerToken` for refusals) runs the grant against the real token endpoint, `authtest.GrantAuthorizer` records the authorizer's requests, and `authtest.RevokeDeviceKey` revokes the key.

## Tokens

- The access token is an RFC 9068 `at+jwt` for the requested resource ([claims](stability.md#tokens)). Its `permissions` are the user's grants on the root group intersected with the resource's `Permissions`: a role that holds `merchant:*` gives `merchant:*` under that ceiling, so the issuer's role catalog decides what the user may do there. `roles` names the user's root role, for display only.
- With the `openid` scope, the answer also carries an ID token for the client (`nonce`, `sid`, `auth_time`, `acr`, `amr`; `profile` and `email` claims by scope).
- Codes last 60 seconds and redeem once; each grant re-checks that the user is live and the sign-in still stands. AuthKit's own API refuses an `at+jwt`.

`authtest.NewAuthorizationServer` runs one over HTTPS for a resource server's or client's tests; `authtest.Attach` drives a Client a host already serves. `CodeFlow.Consent` (or `ApproveConsent`) approves a group client's consent screen.

## Resource servers

A resource server trusts the issuer for its own resource ID, from the JWKS alone:

```go
v := verify.NewVerifier(
	verify.WithDPoP(rdb), // spent proofs in Redis; nil keeps them in memory (one node)
	verify.WithPublicURL("https://api.example.com"),
	verify.WithDPoPNonce(nonceKey), // optional: RFC 9449 server nonces
)
err := v.AddIssuer("https://myapp.com", []string{"https://api.example.com"}, verify.IssuerOptions{
	JWKSURI: "https://myapp.com/.well-known/jwks.json",
})
mux.Handle("/v1/", verify.Required(v)(api))
```

- `Claims.Subject` is the user, `ClientID` the client, `DeviceKeyID` the device key a jwt-bearer token's capability stands on, `Scopes` (`HasScope`) and `Permissions` (`HasPermission`) what it was granted; `Roles` is for display. A token whose `sub` is its `client_id` is the client acting for itself (`Kind` `verify.TokenOAuthClient`). `AuthorizationDetails` is the raw RFC 9396 array, `Invoker` who acts for the user (RFC 8693's actor claim, `act.sub`: the workload after jwt-bearer; empty otherwise), and `CustomClaims` the issuer's URI-named claims.
- A `cnf.jkt` token needs a fresh, single-use DPoP proof of its key on every request. Spent proofs are kept in the Redis given to `WithDPoP`, shared by every replica, or with nil in the process's memory, for one node; while Redis fails, each process keeps its own. With `WithDPoPNonce`, a proof without a current nonce is 401 `use_dpop_nonce` carrying a `DPoP-Nonce` header to retry with. A host writing its own refusals calls `verify.DPoPChallenge` first for the `WWW-Authenticate` and `DPoP-Nonce` headers; browser clients need both exposed by CORS.
