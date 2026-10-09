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

- There is no dynamic registration: every client is first-party, so sign-in needs no consent screen, except for a [lasting or structured grant](#grant-extensions).
- A confidential client sets `SecretSHA256`, the hex SHA-256 of a secret of at least 32 random bytes; AuthKit never holds the secret. A public client must prove a DPoP key (RFC 9449) at the token endpoint, so its tokens are always sender-bound; so must every jwt-bearer request.
- Redirect URIs match exactly: https, or http on a loopback host.

## Endpoints

Beneath the issuer's path, as the metadata at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`) lists them:

| Endpoint | Does |
|---|---|
| `/oauth2/authorize` | authorization code with PKCE S256 (required), `resource` (RFC 8707), `authorization_details` (RFC 9396), `prompt=none\|login`, `max_age`; the response carries `iss` (RFC 9207) |
| `/oauth2/token` | the grants below; a `DPoP` proof binds the tokens to its key (`token_type` `DPoP`, `cnf.jkt`) |
| `/oauth2/revoke` | RFC 7009: ends a refresh token's family; any token answers 200 |
| `/oauth2/userinfo` | the user's claims, for an access token with the `openid` scope (a DPoP-bound one with its proof) |
| `/oauth2/end_session` | RP-initiated logout: ends the sign-in `id_token_hint` names |

Errors are OAuth's `{error, error_description}`. Until the client and redirect URI check out, the authorize endpoint answers itself; after that it redirects back to the client with the error.

## Signing in

The authorize endpoint stores the request and sends the browser to the SPA at `Frontend.AuthorizePath` (`/authorize`) with `?authorization=<id>`. The SPA:

1. reads the request: `GET {api}/oauth2/authorizations/{id}` (the client's name, scopes, `authorization_details`, `prompt`, `max_age`);
2. signs the user in as usual, second factors included;
3. approves it with that sign-in, a session or a device key: `POST {api}/oauth2/authorizations/{id}/approve` answers `{redirect_to}`, the client's redirect URI with a one-time code. A request asking for a fresher sign-in than the user's (`prompt=login`, `max_age`) answers 403 `step_up_required`; step up and approve again.

auth-ui's `OAuthAuthorize` component is that page. It asks the user to allow a request for `offline_access` or `authorization_details` before approving it.

For `prompt=none` with nobody signed in, or when the user refuses, the SPA declines: `POST {api}/oauth2/authorizations/{id}/decline` with `{"error": "login_required"}` (or `access_denied`, `interaction_required`).

## Grants

| Grant | For | Answer |
|---|---|---|
| `authorization_code` | a browser or server client signing the user in, with PKCE; `dpop_jkt` on the authorize request binds the code to the key | access token, ID token with `openid`, refresh token with `refresh_token` |
| `refresh_token` | the same client, proving the same DPoP key; `scope` may narrow | rotated tokens with live permissions |
| `urn:ietf:params:oauth:grant-type:token-exchange` | a host frontend (RFC 8693): `subject_token` is the user's AuthKit access token, `subject_token_type` `urn:ietf:params:oauth:token-type:access_token` | an access token for `resource`, on the same sign-in |
| `client_credentials` | a confidential client acting for itself | an access token with `sub` = `client_id` and the client's `Permissions` within the ceiling |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` | a [workload](#workloads) acting for a user (RFC 7523): `assertion` signed by its key, carrying the capability the user's device key signed, with a DPoP proof of the same key | an access token for the user, `act` the workload, bound to its key, carrying the capability's operations until it expires; no refresh token |

Refresh tokens rotate on every use. A family stands on the sign-in it was issued from (an offline grant: on the grant) and lasts `RefreshTokenTTL` (12 hours by default), which rotation never extends; then the client signs in again with `prompt=none`. Presenting a rotated-out token revokes the family, newest token included.

## Grant extensions

For grants a host decides itself, such as a machine acting for a user for days:

```go
deps.OAuthGrants = func(ctx context.Context, r iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
	// r.Kind: consent, refresh_token, token_exchange or client_credentials.
	err := machines.Check(ctx, r.UserID, r.AuthorizationDetails, r.JWKThumbprint)
	if errors.Is(err, errUnknownMachine) {
		return iam.OAuthGrantDecision{}, iam.ErrOAuthGrantRefused
	}
	if err != nil {
		return iam.OAuthGrantDecision{}, err // an outage: retry later
	}
	return iam.OAuthGrantDecision{
		MaxLifetime: 7 * 24 * time.Hour,
		Claims:      map[string]any{"https://hub.example.com/grant": r.GrantID},
	}, nil
}
cfg.AuthorizationServer.Clients = append(cfg.AuthorizationServer.Clients, authkit.OAuthClientConfig{
	ID:                        "hub-cli",
	RedirectURIs:              []string{"http://127.0.0.1/callback"},
	Resources:                 []string{"https://hub.example.com"},
	GrantTypes:                []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken},
	AuthorizationDetailsTypes: []string{"machine"},
	Offline:                   true,
	KeyBound:                  true,
	RefreshTokenTTL:           7 * 24 * time.Hour,
})
```

- **The grant authorizer** (`Deps.OAuthGrants`) decides at consent, at every refresh, at token exchange, at client credentials and at [jwt-bearer](#workloads). Its decision sets the token's `Permissions` (nil: the defaults), its `AuthorizationDetails` (nil: as requested), a `MaxLifetime` from the grant's start, and extra `Claims`, each named by an absolute URI. A permission in an AuthKit persona's namespace must be one the user holds, checked at every mint; the host's own vocabulary is the host's call; either way the token carries it only within the resource's ceiling. `iam.ErrOAuthGrantRefused` refuses: `access_denied` at consent, `invalid_grant` on refresh (which ends the grant), token exchange and jwt-bearer, `unauthorized_client` for client credentials. Any other error is an outage: consent answers 503 `oauth_grant_authorizer_unavailable` with the request still pending; the token endpoint answers 503 `temporarily_unavailable` and the refresh token still works.
- **`authorization_details`** (RFC 9396) is a JSON array of objects, each with a `type` from the client's `AuthorizationDetailsTypes`; up to 16 entries and 8 KiB. It is accepted on the authorization request, token exchange and client credentials, never on a refresh. A client declaring types needs a grant authorizer. The token response and the access token carry what the decision granted.
- **Offline grants**: a client with `Offline` may ask for `offline_access`. Its refresh tokens stand on the grant, not the sign-in: they keep working after the user signs out, and the tokens carry no `sid` and the consent's `auth_time`, `amr` and `acr`. The grant ends with its lifetime, `Client.RevokeOAuthGrant` (by the `GrantID` the authorizer was given), a refused refresh, a change of the account's credentials, `Client.RevokeAccountSessions`, or the account becoming unusable. Signing out, or out of other sessions, leaves it standing.
- **Lifetimes**: `AccessTokenTTL` (up to 15 minutes) and `RefreshTokenTTL` (up to 30 days) override the server's for one client. No token outlives the decision's `MaxLifetime`.
- **Key-bound clients** (`KeyBound`) must send `dpop_jkt` on the authorization request and prove that key (ES256, P-256) at every token request, so the grant and every token are bound to it. The authorizer sees the key as `JWKThumbprint`.
- **Consent**: `prompt=none` cannot grant `offline_access` or `authorization_details` (`consent_required`); `OAuthAuthorize` shows the request and waits for the user.
- A token from token exchange names the exchanging client in `act` (RFC 8693); a jwt-bearer token names the workload (`Invoker`).
- **Device-key sign-ins** approve and exchange like sessions. The grant stands on the device key (`DeviceKeyID` in the authorizer's request, through every refresh): revoking the key ends it unless it is offline. Its tokens name no `sid`, and carry the device-key sign-in's `auth_time`, which `prompt=login` and `max_age` measure; a stale one signs in with the key again.

`authtest.GrantAuthorizer` records every request for a test; `CodeFlow`, `TokenExchange` and `ClientCredentialsRequest` take `AuthorizationDetails`, and `Consent` returns the client redirect, refusals included.

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
	if r.Kind != iam.OAuthGrantJWTBearer {
		return iam.OAuthGrantDecision{}, nil
	}
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
3. AuthKit verifies both signatures, that the device key is live and the user's, that the user is usable, and that the capability, the assertion and the DPoP proof name the same workload key. It then asks the grant authorizer with `Kind` `jwt_bearer`: `UserID`, `DeviceKeyID`, `Resource`, the capability's `AuthorizationDetails`, `JWKThumbprint` (the workload key), and the verified `Assertion` and `Capability` (their ids, times and other claims). The decision may refuse, or narrow `AuthorizationDetails` by dropping entries (each kept entry must be one of the capability's); `Invoker` names the workload in `act` (default: its key thumbprint); `MaxLifetime` and `Claims` work as for every grant. `Permissions` must stay nil.
4. The token is an `at+jwt` with `sub` the user, `act` `{"sub": <Invoker>}`, `cnf.jkt` the workload key, `device_key_id` the capability's key, `authorization_details` as decided, and `permissions` empty; no `scope`, `sid`, `auth_time`, `acr` or `amr`. It lasts until the capability expires (or `MaxLifetime`), not the client's `AccessTokenTTL`, and has no refresh token: one exchange per capability.

Each `jti` redeems once: the assertion's per workload key, the capability's per device key. Nothing is spent until the token is minted, so a failed request may be retried with the same capability.

The client may be public: the assertion and the DPoP proof prove the workload key and the user's signature authorizes it, so a secret shared by a fleet would add only a secret to leak. A stolen token is useless without the workload key, and a stolen capability is useless without the key and its unspent `jti`.

Revoking the device key ends every token its capabilities minted, at once, for a resource server in the issuer's process: `verify.RequireSession` over a `Client.NewVerifier` (or `Client.CheckSession` on the claims) checks the token's device key with one query, answering 401 `session_revoked`.

A refusal is `invalid_grant` with a `reason` beside it: `assertion_invalid`, `assertion_replayed`, `capability_invalid`, `capability_expired`, `capability_replayed`, `device_key_revoked` (unknown, revoked, or a ban revoked it), `key_mismatch` (the capability names another workload key), `user_unavailable` or `refused` (the authorizer). Also `invalid_dpop_proof` (no proof, or reason `key_mismatch` for another key's), `invalid_target` (a resource that is not the capability's, or not the client's), `invalid_scope` (any `scope`), `unauthorized_client` and `temporarily_unavailable` (the authorizer failed).

In tests, `authtest.EnrollDeviceKey` enrolls a device key, `DeviceKey.Capability` signs a capability, `AuthorizationServer.JWTBearer` (`JWTBearerToken` for refusals) runs the grant against the real token endpoint, and `authtest.RevokeDeviceKey` revokes the key.

## Tokens

- The access token is an RFC 9068 `at+jwt` for the requested resource ([claims](stability.md#tokens)). Its `permissions` are the user's grants on the root group intersected with the resource's `Permissions`: a role that holds `merchant:*` gives `merchant:*` under that ceiling, so the issuer's role catalog decides what the user may do there. `roles` names the user's root role, for display only.
- With the `openid` scope, the answer also carries an ID token for the client (`nonce`, `sid`, `auth_time`, `acr`, `amr`; `profile` and `email` claims by scope).
- Codes last 60 seconds and redeem once; each grant re-checks that the user is live and the sign-in still stands. AuthKit's own API refuses an `at+jwt`.

`authtest.NewAuthorizationServer` runs one over HTTPS for a resource server's or client's tests.

## Resource servers

A resource server trusts the issuer for its own resource ID, from the JWKS alone:

```go
v := verify.NewVerifier(
	verify.WithDPoP(replay), // a replay store every replica shares
	verify.WithPublicURL("https://api.example.com"),
	verify.WithDPoPNonce(nonceKey), // optional: RFC 9449 server nonces
)
err := v.AddIssuer("https://myapp.com", []string{"https://api.example.com"}, verify.IssuerOptions{
	JWKSURI: "https://myapp.com/.well-known/jwks.json",
})
mux.Handle("/v1/", verify.Required(v)(api))
```

- `Claims.Subject` is the user, `ClientID` the client, `DeviceKeyID` the device key a jwt-bearer token's capability stands on, `Scopes` (`HasScope`) and `Permissions` (`HasPermission`) what it was granted; `Roles` is for display. A token whose `sub` is its `client_id` is the client acting for itself (`Kind` `verify.TokenOAuthClient`). `AuthorizationDetails` is the raw RFC 9396 array, `Invoker` who acts for the user (RFC 8693's actor claim, `act.sub`: the client after token exchange, the workload after jwt-bearer), and `CustomClaims` the issuer's URI-named claims.
- A `cnf.jkt` token needs a fresh, single-use DPoP proof of its key on every request. With `WithDPoPNonce`, a proof without a current nonce is 401 `use_dpop_nonce` carrying a `DPoP-Nonce` header to retry with. A host writing its own refusals calls `verify.DPoPChallenge` first for the `WWW-Authenticate` and `DPoP-Nonce` headers; browser clients need both exposed by CORS.
