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
- A confidential client sets `SecretSHA256`, the hex SHA-256 of a secret of at least 32 random bytes; AuthKit never holds the secret. A public client must prove a DPoP key (RFC 9449) at the token endpoint, so its tokens are always sender-bound.
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
3. approves it with that sign-in: `POST {api}/oauth2/authorizations/{id}/approve` answers `{redirect_to}`, the client's redirect URI with a one-time code. A request asking for a fresher sign-in than the user's (`prompt=login`, `max_age`) answers 403 `step_up_required`; step up and approve again.

auth-ui's `OAuthAuthorize` component is that page. It asks the user to allow a request for `offline_access` or `authorization_details` before approving it.

For `prompt=none` with nobody signed in, or when the user refuses, the SPA declines: `POST {api}/oauth2/authorizations/{id}/decline` with `{"error": "login_required"}` (or `access_denied`, `interaction_required`).

## Grants

| Grant | For | Answer |
|---|---|---|
| `authorization_code` | a browser or server client signing the user in, with PKCE; `dpop_jkt` on the authorize request binds the code to the key | access token, ID token with `openid`, refresh token with `refresh_token` |
| `refresh_token` | the same client, proving the same DPoP key; `scope` may narrow | rotated tokens with live permissions |
| `urn:ietf:params:oauth:grant-type:token-exchange` | a host frontend (RFC 8693): `subject_token` is the user's AuthKit access token, `subject_token_type` `urn:ietf:params:oauth:token-type:access_token` | an access token for `resource`, on the same sign-in |
| `client_credentials` | a confidential client acting for itself | an access token with `sub` = `client_id` and the client's `Permissions` within the ceiling |

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

- **The grant authorizer** (`Deps.OAuthGrants`) decides at consent, at every refresh, at token exchange and at client credentials. Its decision sets the token's `Permissions` (nil: the defaults), its `AuthorizationDetails` (nil: as requested), a `MaxLifetime` from the grant's start, and extra `Claims`, each named by an absolute URI. A permission in an AuthKit persona's namespace must be one the user holds, checked at every mint; the host's own vocabulary is the host's call; either way the token carries it only within the resource's ceiling. `iam.ErrOAuthGrantRefused` refuses: `access_denied` at consent, `invalid_grant` on refresh (which ends the grant) and token exchange, `unauthorized_client` for client credentials. Any other error is an outage: consent answers 503 `oauth_grant_authorizer_unavailable` with the request still pending; the token endpoint answers 503 `temporarily_unavailable` and the refresh token still works.
- **`authorization_details`** (RFC 9396) is a JSON array of objects, each with a `type` from the client's `AuthorizationDetailsTypes`; up to 16 entries and 8 KiB. It is accepted on the authorization request, token exchange and client credentials, never on a refresh. A client declaring types needs a grant authorizer. The token response and the access token carry what the decision granted.
- **Offline grants**: a client with `Offline` may ask for `offline_access`. Its refresh tokens stand on the grant, not the sign-in: they keep working after the user signs out, and the tokens carry no `sid` and the consent's `auth_time`, `amr` and `acr`. The grant ends with its lifetime, `Client.RevokeOAuthGrant` (by the `GrantID` the authorizer was given), a refused refresh, a change of the account's credentials, `Client.RevokeAccountSessions`, or the account becoming unusable. Signing out, or out of other sessions, leaves it standing.
- **Lifetimes**: `AccessTokenTTL` (up to 15 minutes) and `RefreshTokenTTL` (up to 30 days) override the server's for one client. No token outlives the decision's `MaxLifetime`.
- **Key-bound clients** (`KeyBound`) must send `dpop_jkt` on the authorization request and prove that key (ES256, P-256) at every token request, so the grant and every token are bound to it. The authorizer sees the key as `JWKThumbprint`.
- **Consent**: `prompt=none` cannot grant `offline_access` or `authorization_details` (`consent_required`); `OAuthAuthorize` shows the request and waits for the user.
- A token from token exchange names the exchanging client in `act` (RFC 8693).

`authtest.GrantAuthorizer` records every request for a test; `CodeFlow`, `TokenExchange` and `ClientCredentialsRequest` take `AuthorizationDetails`, and `Consent` returns the client redirect, refusals included.

### From delegated tokens

Delegated and service tokens are deprecated; each use has an OAuth replacement:

| Delegated | OAuth |
|---|---|
| `POST /delegated/token`, `Client.MintDelegatedAccessToken` for a signed-in user | token exchange by a client with `GrantTokenExchange` |
| a delegate acting for days (a worker, a machine) | a code-flow client with `Offline`, `KeyBound` and its own `RefreshTokenTTL`, refreshing with its DPoP key |
| `Deps.DelegatedAuthorization` | `Deps.OAuthGrants` |
| a requested grant or `attributes` | `authorization_details`; the decision's `Claims` |
| a delegate certificate (`cnf.x5t#S256`) | the key-bound DPoP key (`cnf.jkt`); the authorizer checks `JWKThumbprint` |
| `Client.MintServiceJWT`, `remote-application-access+jwt` | client credentials |
| `verify.Claims.DelegatedSubject`, `Attributes` | `Subject`, `AuthorizationDetails`, `CustomClaims`, `Actor` |

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

- `Claims.Subject` is the user, `ClientID` the client, `Scopes` (`HasScope`) and `Permissions` (`HasPermission`) what it was granted; `Roles` is for display. A token whose `sub` is its `client_id` is the client acting for itself (`Kind` `iam.ActorOAuthClient`). `AuthorizationDetails` is the raw RFC 9396 array, `Actor` the client acting for the user after token exchange, and `CustomClaims` the issuer's URI-named claims.
- A `cnf.jkt` token needs a fresh, single-use DPoP proof of its key on every request. With `WithDPoPNonce`, a proof without a current nonce is 401 `use_dpop_nonce` carrying a `DPoP-Nonce` header to retry with. A host writing its own refusals calls `verify.DPoPChallenge` first for the `WWW-Authenticate` and `DPoP-Nonce` headers; browser clients need both exposed by CORS.
