# Resource server

With `Config.Resource`, AuthKit verifies every credential a service accepts, and `Client.Authenticator()` hands a library such as OpenRails one answer for all of them. AuthKit accepts:

- its own sessions and API keys;
- the RFC 9068 access tokens (`at+jwt`) its own authorization server mints for `Resource.ID`;
- the access tokens its trusted issuers mint for `Resource.ID`.

```go
cfg.Resource = authkit.ResourceConfig{
	ID: "https://api.example.com", // RFC 8707: an accepted token's aud
	Scopes: map[string][]string{   // RFC 6749 §3.3: what each scope may reach
		"api:merchant": {"merchant:*"},
		"api:self":     {},
	},
}
```

```yaml
resource:
  id: https://api.example.com
  public_url: https://api.example.com   # where a DPoP proof's htu points; default: id's origin
  scopes:
    "api:merchant": ["merchant:*"]
    "api:self": []
```

## Trusted issuers

A trusted issuer is a [remote application](tokens.md#remote-applications): an issuer controlled by one group, holding a role there. Its tokens act only in that group.

- `Verified.BoundScope()` (helpers/auth `Bound`) is the application's group. `Can` is false in any other scope.
- In that group, `Can` grants a permission only when all three hold:
  - the token carries it, in its `permissions` claim or through a role its `roles` claim names (RFC 9068 §2.2.3.1), mapped by the application's `RoleMap`;
  - the application's live role covers it;
  - one of the token's scopes covers it (`Resource.Scopes`).
- An issuer is trusted in exactly one group. `Client.DeclareRemoteApplications(ctx, group, apps)` declares a group's issuers from configuration; `UpsertRemoteApplication` registers one at run time.
- Keys come from `PublicKeys`, from `JWKSURI`, or with neither from the issuer's RFC 8414 metadata (`/.well-known/oauth-authorization-server`, else `/.well-known/openid-configuration`). Disabling or deleting the application stops its tokens on the next request.
- The identity is the issuer's user, or the issuer's client acting for itself (`sub` = `client_id`, an application). The invoker is the user unless an RFC 8693 `act` claim names another. Contact claims (OIDC Core §5.1) fill the identity's email and username.
- `CheckRecentSignIn` reads `auth_time`. A sign-in older than 15 minutes is RFC 9470's step-up: `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=900`.

## A trusted application without an authorization server

A trusted issuer's backend can mint a customer token for its user without running an authorization server (RFC 7523 §2.1):

1. It signs a short assertion with its remote application's key:
   - `iss`: its issuer;
   - `sub`: its user;
   - `aud`: AuthKit's token endpoint;
   - `exp`: at most 5 minutes ahead;
   - `jti`: 16-128 characters, spent once;
   - optionally `email`, `email_verified`, `name` and `preferred_username`.
2. Its frontend posts the assertion to AuthKit's token endpoint, with no client: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion`, and optionally `scope` and a DPoP proof.
3. The answer is an access token for `Resource.ID`:
   - it acts for that user in the application's group and holds no permissions;
   - its `client_id` is the application's issuer;
   - it is DPoP-bound when the frontend proved a key, and a bearer token otherwise.

With `Config.Resource`, the token endpoint is mounted even without an authorization server, and it answers any origin, since it takes no cookies.

## DPoP

`sign_in.dpop` sets how this instance issues tokens to its own users. It never changes how tokens are validated: a bound token needs its proof, an unbound token is a bearer token, whoever issued it.

- **Validation, for every token any instance verifies:** a bound token (`cnf.jkt`) is accepted only with a fresh proof of its key (RFC 9449 §7), never as Bearer (§7.2).
- **Proofs and nonces:**
  - Spent proofs are kept in `Deps.Redis`, or in memory without it (one node).
  - A proof must carry a server nonce (RFC 9449 §9). A proof without one gets `401 use_dpop_nonce` with a `DPoP-Nonce` to retry with. Nonces are kept in the same store, so there is no key to configure.
  - `Deps.ResourceHosts` lets a proof name a host other than `public_url` that the host vouches for, such as a tenant's API host.
- **Issuance (`sign_in.dpop`):**
  - `optional`, the default, lets each client choose at sign-in. A sign-in or refresh that proves a key binds the session for good: its access tokens carry `cnf.jkt`, and every refresh proves the same key (RFC 9449 §5). A client that proves no key gets bearer tokens, and a public client's refresh tokens then rotate (RFC 9700 §4.14.2).
  - `required` refuses a sign-in, a user grant or a refresh without a proof.
  - Neither setting ever covers API keys, client credentials or service tokens.
- **OIDC sign-in:** a browser sign-in through an identity provider binds its session through `dpop_jkt` (RFC 9449 §10) on the start URL, or through the proof on the JSON start.
- **Discovery:** clients read the mode from `GET {api}/capabilities` (`dpop`). auth-ui binds with `createAuthClient({ dpop: true })`, and binds anyway when AuthKit requires it.

## For a library

- `Client.Authenticator()` lists its credential headers (helpers/auth `Headers`): `Authorization` and `DPoP` allowed, `WWW-Authenticate` and `DPoP-Nonce` exposed. Merge them into CORS.
- API keys report their group as `BoundScope`.
- `Authenticate` spends the request's DPoP proof, so call it once per request. Behind one of AuthKit's own gates, it reuses the gate's verification instead.
