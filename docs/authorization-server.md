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
	}},
}
```

- There is no dynamic registration and no consent screen: every client is first-party.
- A confidential client sets `SecretSHA256`, the hex SHA-256 of a secret of at least 32 random bytes; AuthKit never holds the secret.
- Redirect URIs match exactly: https, or http on a loopback host.

## Endpoints

Beneath the issuer's path, as the metadata at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`) lists them:

| Endpoint | Does |
|---|---|
| `/oauth2/authorize` | authorization code with PKCE S256 (required), `resource` (RFC 8707), `prompt=none\|login`, `max_age`; the response carries `iss` (RFC 9207) |
| `/oauth2/token` | redeems a code once, for the client, redirect URI and verifier it was issued to |
| `/oauth2/userinfo` | the user's claims, for an access token with the `openid` scope |
| `/oauth2/end_session` | RP-initiated logout: ends the sign-in `id_token_hint` names |

Errors are OAuth's `{error, error_description}`. Until the client and redirect URI check out, the authorize endpoint answers itself; after that it redirects back to the client with the error.

## Signing in

The authorize endpoint stores the request and sends the browser to the SPA at `Frontend.AuthorizePath` (`/authorize`) with `?authorization=<id>`. The SPA:

1. reads the request: `GET {api}/oauth2/authorizations/{id}` (the client's name, `prompt`, `max_age`);
2. signs the user in as usual, second factors included;
3. approves it with that sign-in: `POST {api}/oauth2/authorizations/{id}/approve` answers `{redirect_to}`, the client's redirect URI with a one-time code. A request asking for a fresher sign-in than the user's (`prompt=login`, `max_age`) answers 403 `step_up_required`; step up and approve again.

For `prompt=none` with nobody signed in, or when the user refuses, the SPA declines: `POST {api}/oauth2/authorizations/{id}/decline` with `{"error": "login_required"}` (or `access_denied`, `interaction_required`).

## Tokens

- The access token is an RFC 9068 `at+jwt` for the requested resource ([claims](stability.md#tokens)). Its `permissions` are the user's grants on the root group intersected with the resource's `Permissions`: a role that holds `merchant:*` gives `merchant:*` under that ceiling, so the issuer's role catalog decides what the user may do there. `roles` names the user's root role, for display only.
- With the `openid` scope, the answer also carries an ID token for the client (`nonce`, `sid`, `auth_time`, `acr`, `amr`; `profile` and `email` claims by scope).
- Codes last 60 seconds and redeem once; each grant re-checks that the user is live and the sign-in still stands. AuthKit's own API refuses an `at+jwt`.

`authtest.NewAuthorizationServer` runs one over HTTPS for a resource server's or client's tests.
