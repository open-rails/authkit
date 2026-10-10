# SCIM provisioning and user info

AuthKit is the directory: other services learn who a user is from it, four ways. It also keeps a [directory](#directory) of the users other issuers push to it.

| Way | For |
|---|---|
| [Push](#push) | a service that keeps its own copy: AuthKit sends every account to its SCIM 2.0 endpoint, such as another AuthKit's [directory](#directory) |
| [Pull](#pull) | a service that reads on demand: AuthKit's read-only SCIM 2.0 endpoint |
| [In process](#in-process) | a library embedded in the same binary: `Client.UserInfo()` is a `helpers/userinfo.Lookup` |
| [Token claims](#token-claims) | a resource server that meets a user on the user's first request |

What push, pull and in process show of an account: its id, its username (also the name; AuthKit keeps no other), its email **only once verified** (an unproven address may be someone else's), and whether it is active (neither deleted nor banned).

## Push

```go
cfg.Provisioning = authkit.ProvisioningConfig{
	Targets: []authkit.ProvisioningTarget{{
		Name:        "billing",
		URL:         "https://billing.example.com/billing/v1/app/scim/v2",
		BearerToken: os.Getenv("BILLING_SCIM_TOKEN"),
	}},
}
```

- A target is a SCIM base `URL`, or a `Handler` served in process. It authenticates with a static `BearerToken` (another AuthKit's [directory](#directory): an API key bound to your remote application there) or `ClientCredentials` (an OAuth 2.0 token endpoint, client id and secret, optional `Scopes` and `Resource`).
- Every change to what a SCIM User shows (creation, email or its verification, username, ban, deletion, restore, purge) records the account for each target in the change's own transaction, whichever code or SQL makes it: triggers on `users` write the outbox.
- Every `Interval` (5 minutes) a River job per target sends each pending account's latest state, one operation per account, in `POST /Bulk` requests within the target's advertised `maxOperations` and `maxPayloadSize` (`/ServiceProviderConfig`). A target without bulk gets the same operations as single requests.
- An account the target does not hold yet is `POST /Users` with `externalId` = the account id; afterwards `PUT /Users/{the target's id}`. Every resource carries `meta.lastModified`, when what it shows last changed, so a target keeps the newest of what it hears. A purged account is `DELETE`d. Deletion within its 30 days and bans push `active: false`; a temporary ban's end pushes `active: true`.
- Only what the target accepted leaves the outbox. An unreachable target, or one refusing a whole request, is retried from `Interval` doubling up to an hour; a refused account waits its own backoff while the rest go on. A create the target answers 409 is matched to its user by `externalId` and replaced.
- A new target first gets every account (the initial sync, in bulk too). Every `ReconcileInterval` (a day; negative turns it off) AuthKit lists the target's users and queues every account whose resource drifted, went missing, or belongs to a purged account; a resource the listing did not show is asked for by its id. The listing saves its place with each page, so a reconciliation of a large directory spans runs. A resource whose `externalId` is not an account AuthKit pushed is left alone.
- Status: `Client.ProvisioningTargets` and `GET /api/v1/admin/provisioning/targets` (`root:users:read`) give each target's `last_success_at`, `failing_since`, `last_error` and `backlog` (accounts waiting).
- A target removed from the configuration is forgotten, with its outbox, when its app's River fleet starts. Apps sharing one account store each push to their own targets; every app's changes reach every target.

## Pull

With the [authorization server](authorization-server.md) on, AuthKit serves a read-only SCIM 2.0 service provider beneath the issuer: `{issuer}/scim/v2`.

| Route | Answers |
|---|---|
| `GET /scim/v2/Users/{id}` | one account, `id` its AuthKit id |
| `GET /scim/v2/Users` | every account by id, `startIndex` and `count` (at most 200); `filter` takes `id eq`, `userName eq` and `emails.value eq` terms joined by `or` |
| `GET /scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | discovery |
| `POST /scim/v2/Users`, `PUT`, `PATCH`, `DELETE /scim/v2/Users/{id}`, `POST /scim/v2/Bulk` | 501 |

It takes a client-credentials access token from this issuer for the resource `{issuer}/scim/v2` with scope `scim:read` (DPoP-bound or bearer). AuthKit declares that resource itself; a client lists it:

```go
cfg.AuthorizationServer.Clients = append(cfg.AuthorizationServer.Clients, authkit.OAuthClientConfig{
	ID:           "directory-sync",
	SecretSHA256: directorySyncSecretSHA256,
	GrantTypes:   []authkit.OAuthGrantType{authkit.GrantClientCredentials},
	Resources:    []string{issuer + "/scim/v2"},
})
```

Errors are SCIM's (`application/scim+json`): 401 and 403 with a `WWW-Authenticate` challenge, 400 `invalidFilter`, 404.

## In process

`Client.UserInfo()` returns a `userinfo.Lookup` (`github.com/open-rails/helpers/userinfo`): its `Get(ctx, ids)` returns the live accounts among ids, and `Search(ctx, query, limit)` those whose verified email or username contains query. Each read is current; nothing is copied. An embedded OpenRails takes `Deps.UserInfo: auth.UserInfo()`.

## Token claims

`ResourceServerConfig.ContactClaims` puts the contact in every user access token for that resource: `email` with `email_verified` (as OIDC has it: keep the address only when verified), `preferred_username`, `name` and `updated_at` (seconds since the epoch, when one of them last changed). `verify.Claims` reads them as `Email`, `EmailVerified`, `Username`, `Name` and `UpdatedAt`. Tokens for other resources carry only what their scopes grant.

## Directory

A group whose persona has `RemoteApplications` keeps a directory of its remote applications' users, a SCIM 2.0 service provider (RFC 7643, RFC 7644) beneath the issuer at `{issuer}/directory/scim/v2`. Another AuthKit's [push](#push), Okta or Microsoft Entra ID provisions it, and a library reads it with `Client.RemoteUserInfo`.

**Tenant.** The credential names the directory (RFC 7644 §6.1): one issuer's users in one group. A user is its issuer and subject together (OpenID Connect Core §2, §5.7), so two issuers' users never mix, and another group's credential sees none of them (404).

- An API key bound to a remote application of its group: `iam.NewAPIKey.ProvisionsFor`, or `provisions_for` on `POST /api/v1/groups/{group_id}/api-keys`. It is sent as `Authorization: Bearer` (RFC 6750 §2.1): a push target's `BearerToken`, or Okta's and Entra's secret token. It is deleted with the application.
- The remote application's own access token (client credentials, `sub` equal to `client_id`), once `Client.Authenticator()` accepts trusted issuers' tokens.

A credential with no application, or whose application is disabled, is refused 403. Reads need `<persona>:directory:read` in the group, writes `<persona>:directory:manage`.

```go
merchant := roles.Persona("merchant", authkit.APIKeys, authkit.RemoteApplications)
provisioner := merchant.Role("provisioner", merchant.Directory.All())
// For each pushing application, registered in its merchant's group:
key, err := ak.CreateAPIKey(ctx, iam.SystemIdentity(), group, iam.NewAPIKey{
	Name: "directory", Role: provisioner, ProvisionsFor: app.ID,
})
```

| Route | Answers |
|---|---|
| `GET /Users/{id}`, `GET /Users` | the users the tenant provisioned, by `startIndex` and `count` (at most 200); `filter` takes `externalId`, `userName`, `id` and `emails.value` `eq` terms joined by `or` (§3.4.2) |
| `POST /Users` | create (§3.3): 201 with `Location`; 409 `uniqueness` when the `externalId` or `userName` is taken |
| `PUT /Users/{id}` | replace (§3.5.1): what the body omits is cleared |
| `PATCH /Users/{id}` | `add`, `replace`, `remove` (§3.5.2), all or none |
| `DELETE /Users/{id}` | delete (§3.6): the user is deleted, not deactivated |
| `POST /Bulk` | up to 1000 operations or 1 MiB (§3.7), each on its own; `failOnErrors` stops early |
| `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | discovery (§4); no credential needed |

- **User.** `externalId` is the user's subject at its issuer (an access token's `sub`) and is required; `userName` is required and unique among the issuer's users in the group. AuthKit keeps `displayName`, `name` (`formatted`, `givenName`, `familyName`), one address (the primary, else the first, with its `type`) and `active` (default `true`). Other attributes, another schema's included, are accepted and ignored (§3.3). A client's `meta` is ignored (RFC 7643 §3.1); the last write wins.
- **PATCH** takes Okta's and Entra's shapes: operations without a path, `op` in any case, a value filter on `emails` (`emails[type eq "work"].value`: one equality on `value`, `type` or `primary`), and `"True"`/`"False"` for `active`. One address is kept, so every `emails` path addresses it; an `add` whose filter matches nothing adds it with the filter's `type`, a `replace` is 400 `noTarget`.
- **Errors** are RFC 7644 §3.12 bodies as `application/scim+json`: 400 with a `scimType`, 401 with RFC 6750 §3's `WWW-Authenticate`, 403, 404, 409 `uniqueness`, 413.
- **Verified addresses.** SCIM's User has no verification flag (RFC 7643 §4.1.2), so an address pushed is one the issuer asserts; AuthKit's own push sends an address only once verified. Point only such a directory at it.

`Client.RemoteUserInfo(ref, issuer)` is the group's users of issuer as a `helpers/userinfo.Lookup`, keyed by subject: the email, the name (`displayName`, else `name.formatted`, else the given and family names) and the username. An inactive user (`active: false`) is absent. A library reads a customer's contact through it by the issuer and subject of the customer's token.

Retention: a SCIM `DELETE` deletes the user, and deleting the group deletes its directory. Migration 0013 adds `remote_users` and `api_keys.provisions_for`.
