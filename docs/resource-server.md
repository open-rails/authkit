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
  scopes:
    "api:merchant": ["merchant:*"]
    "api:self": []
```

## Trusted issuers

A trusted issuer is a [remote application](tokens.md#remote-applications): an issuer controlled by one group, holding a role there. Its tokens act only in that group.

- `Verified.BoundScope()` (authkit/auth `Bound`) is the application's group. `Can` is false in any other scope.
- In that group, `Can` grants a permission only when all three hold:
  - the token carries it, in its `permissions` claim or through a role its `roles` claim names (RFC 9068 §2.2.3.1), mapped by the application's `RoleMap`;
  - the application's live role covers it;
  - one of the token's scopes covers it (`Resource.Scopes`).
- An issuer is trusted in exactly one group. `Client.DeclareRemoteApplications(ctx, group, apps)` declares a group's issuers from configuration; `UpsertRemoteApplication` registers one at run time.
- Over HTTP, a person holding `<persona>:credentials:manage` registers the group's own, with a recent sign-in: `GET /groups/{group_id}/remote-applications` (`credentials:read`), `POST` (an issuer with a `jwks_uri` or `public_keys`; one registered anywhere already is `remote_application_issuer_conflict`), `PATCH /groups/{group_id}/remote-applications/{id}` (`enabled`, or a new trust source) and `DELETE`. An API key registers none, and one the operator declared changes only in configuration.
- Keys come from `PublicKeys`, from `JWKSURI`, or with neither from the issuer's RFC 8414 metadata (`/.well-known/oauth-authorization-server`, else `/.well-known/openid-configuration`). Disabling or deleting the application stops its tokens on the next request.
- Discovery is cached like the keys: concurrent requests share one fetch, and a failed one is not retried for five seconds, so tokens naming an unreachable issuer make at most one attempt in that time.
- Keys and metadata are fetched through AuthKit's SSRF guard: it dials only public unicast addresses (no private, loopback, link-local, documentation, IPv4-compatible, 6to4, Teredo or other reserved range; a NAT64 address counts as the IPv4 address it reaches), follows at most five redirects, and never one from https to http. An application the host declares (`Config.RemoteApplications`, `DeclareRemoteApplications`, the bootstrap manifest) may fetch from a private network (`iam.RemoteApplication.PrivateNetwork`); one registered at run time never may, and a private `jwks_uri` is refused at its registration. A loopback issuer admits private addresses for every application.
- Each of `PublicKeys` has a distinct `kid`: its `KID`, else its JWK's, so a PEM key needs `KID`; registration refuses one without (`invalid_remote_application`). A token or assertion naming no `kid` is verified with the issuer's only key.
- The identity is the issuer's user, or the issuer's client acting for itself (`sub` = `client_id`, an application). The invoker is the user unless an RFC 8693 `act` claim names another. Contact claims (OIDC Core §5.1) fill the identity's email and username.
- `CheckRecentSignIn` reads `auth_time`. A sign-in older than 15 minutes is RFC 9470's step-up: `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=900`.

## Federated grants

A group may grant roles to a trusted issuer's users by email:

1. An owner invites an address with a role: `CreateInvitation(ctx, who, group, iam.NewInvitation{Email: …, Role: …})`.
2. The user signs in at their issuer. With a token whose verified email is the invitation's, `Client.RemoteInvitations(ctx, v)` lists the invitation and `Client.AcceptRemoteInvitation(ctx, v, id)` accepts it, once.
3. The user (their record in the group's [directory](scim.md#directory)) then holds the role in the group. Their tokens hold its permissions there, within the application's role as always.

Acceptance is the same redemption a native account's is. It is refused while invitations are off (`iam.RouteInvitations` unmounted: `invitations_disabled`), for an invitation revoked, issued under another application's catalog, or whose inviter is gone or no longer covers its role (`invitation_revoked`), expired (`invitation_expired`) or used (`invitation_not_found`), and for a user the directory marks inactive. A role that would strip grants the user holds there is `iam.ErrRoleAssignmentEscalation` and the user keeps its role; a role that requires MFA is not assignable, since AuthKit cannot check another issuer's second factor. A user already holding the role succeeds without using the invitation.

`Client.RemoteUserRoles` lists these grants, and `Client.RemoveRemoteUserRole` ends one; ending one needs `<persona>:members:manage` and coverage of the role.

## A trusted application without an authorization server

A trusted issuer's backend can mint a customer token for its user without running an authorization server (RFC 7523 §2.1):

1. It signs a short assertion with its remote application's key:
   - `iss`: its issuer;
   - `sub`: its user;
   - `aud`: AuthKit's token endpoint;
   - `exp`: at most 2 minutes ahead (RFC 7523 §3);
   - `jti`: 16-128 characters, spent once, where DPoP proofs are (`Deps.Replays`, else `Deps.Redis`, else memory);
   - optionally `email`, `email_verified`, `name` and `preferred_username`.
2. Its frontend posts the assertion to AuthKit's token endpoint, with no client: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion`, and optionally `scope` and a DPoP proof.
3. The answer is an access token for `Resource.ID`:
   - it acts for that user in the application's group and holds no permissions;
   - its `client_id` is the application's issuer, and at `Client.Authenticator()` its Verified's `auth.Asserted` capability answers `Asserted()` true (false for every other credential), so a library tells a customer token from a staff one without comparing issuers;
   - it is DPoP-bound when the frontend proved a key, and a bearer token otherwise;
   - it lasts 15 minutes.

With `Config.Resource`, the token endpoint is mounted even without an authorization server, and it answers any origin, since it takes no cookies.

## DPoP

This instance binds every session and user grant it issues to a DPoP key. That never changes how tokens are validated: a bound token needs its proof, an unbound token is a bearer token, whoever issued it.

- **Validation, for every token any instance verifies:** a bound token (`cnf.jkt`) is accepted only with a fresh proof of its key (RFC 9449 §7), never as Bearer (§7.2).
- **Proofs and nonces:**
  - Spent proofs are kept in `Deps.Replays`, else `Deps.Redis`, else in memory (one node). While that store fails, proofs are refused.
  - A proof must carry a server nonce (RFC 9449 §9). A proof without one gets `401 use_dpop_nonce` with a `DPoP-Nonce` to retry with. Nonces are kept in `Deps.Redis`, else in memory, so there is no key to configure.
  - `Deps.ResourceHosts` lets a proof name a host other than `Resource.ID`'s that the host vouches for, such as a tenant's API host.
- **Issuance:** a sign-in, a user grant (code, refresh, token exchange) or a refresh without a proof is refused. The proven key binds the session for good: its access tokens carry `cnf.jkt`, and every refresh proves the same key (RFC 9449 §5). API keys, client credentials and service tokens never need one.
- **OIDC sign-in:** a browser sign-in through an identity provider binds its session through `dpop_jkt` (RFC 9449 §10) on the start URL, or through the proof on the JSON start.
- **Discovery:** `GET {api}/capabilities` answers `dpop: "required"`. auth-ui binds from the first sign-in with `createAuthClient({ dpop: true })`, and otherwise once AuthKit refuses an unbound one.

## For a library

- `Client.Authenticator()` lists its credential headers (authkit/auth `Headers`): `Authorization` and `DPoP` allowed, `WWW-Authenticate` and `DPoP-Nonce` exposed. Merge them into CORS.
- API keys report their group as `BoundScope`.
- `Authenticate` spends the request's DPoP proof, so call it once per request. Behind one of AuthKit's own gates, it reuses the gate's verification instead.
