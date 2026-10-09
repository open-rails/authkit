# SCIM provisioning and contacts

AuthKit is the directory: other services learn who a user is from it, four ways.

| Way | For |
|---|---|
| [Push](#push) | a service that keeps its own copy (OpenRails' customer contacts): AuthKit sends every account to its SCIM 2.0 endpoint |
| [Pull](#pull) | a service that reads on demand: AuthKit's read-only SCIM 2.0 endpoint |
| [In process](#in-process) | a library embedded in the same binary: `*authkit.Client` is a `helpers/contacts.Source` |
| [Token claims](#token-claims) | a resource server that meets a user on the user's first request |

What push, pull and in process show of an account: its id, its username (also the name; AuthKit keeps no other), its email **only once verified** (an unproven address may be someone else's), and whether it is active (neither deleted nor banned).

## Push

```go
cfg.Provisioning = authkit.ProvisioningConfig{
	Targets: []authkit.ProvisioningTarget{{
		Name:        "billing",
		URL:         "https://billing.example.com/scim/v2",
		BearerToken: os.Getenv("BILLING_SCIM_TOKEN"),
	}},
}
```

- A target is a SCIM base `URL`, or a `Handler` served in process (an embedded OpenRails passes `bill.SCIMHandler()`, which takes no credential; nothing crosses the network). It authenticates with a static `BearerToken` (OpenRails: a provisioning token) or `ClientCredentials` (an OAuth 2.0 token endpoint, client id and secret, optional `Scopes` and `Resource`; OpenRails takes scope `scim` for its resource).
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

`*authkit.Client` implements `contacts.Source` (`github.com/open-rails/helpers/contacts`): `Contacts(ctx, ids)` returns the live accounts among ids, and `SearchContacts(ctx, query, limit)` those whose verified email or username contains query. Each read is current; nothing is copied. An embedded OpenRails takes `Deps.Contacts: auth`.

## Token claims

`ResourceServerConfig.ContactClaims` puts the contact in every user access token for that resource: `email` with `email_verified` (as OIDC has it: keep the address only when verified), `preferred_username`, `name` and `updated_at` (seconds since the epoch, when one of them last changed). `verify.Claims` reads them as `Email`, `EmailVerified`, `Username`, `Name` and `UpdatedAt`. Tokens for other resources carry only what their scopes grant.
