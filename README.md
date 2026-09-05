# AuthKit

Embedded auth library for Go services: users, sessions, MFA, passkeys, device
keys, OAuth/OIDC and Solana login, RBAC permission groups, API keys, signed
documents and delegated tokens, running in your process against your Postgres
(18+) and Redis. `cmd/authkit-server` is the dev/CI harness that boots this
surface for `docker compose`, not a product.

Modules: `github.com/open-rails/authkit`, plus `adapters/gin` and
`adapters/riverjobs` as separate modules so gin and river never enter the root
`go.mod`.

## Migrations

```go
import "github.com/open-rails/authkit/authkitmigrate"

res, err := authkitmigrate.New(pool, nil).Migrate(ctx) // &authkitmigrate.Config{Schema: "…"} for a non-default schema
```

Idempotent; `Validate(ctx)` reports pending migrations without applying. Run
it before `embedded.New`.

## Construction

`embedded.New(cfg, deps)` builds the engine (`*embedded.Client`, which
implements `authkit.Client`); `authhttp.New(client, cfg)` builds the HTTP
transport; `authhttp.MountHandler` returns the whole surface — JWKS at
`/.well-known/jwks.json`, browser OIDC under `/oidc`, the JSON API under
`APIPrefix` (default `/api/v1`) — as one `http.Handler`. Every dev-only
behaviour is an explicit field whose default is the safe one
(`Keys.AllowEphemeralDevKeys`, `Ephemeral.AllowMemory` when no Redis is wired,
`Applications.AllowPrivateNetworkJWKS`, `Registration.AllowMissingSenders`),
and `authhttp.Config` always needs a client-IP posture: `TrustedProxies`,
`CloudflareProxies`, `DirectPeerIP` or `ClientIP`.

```go
import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/verify"
)

func setupAuth(pg *pgxpool.Pool, rdb *redis.Client, mailer embedded.EmailSender) (*gin.Engine, error) {
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "https://app.example.com",
			IssuedAudiences:     []string{"myapp"},
			ExpectedAudiences:   []string{"myapp"},
			AccessTokenDuration: 15 * time.Minute,
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://app.example.com"},
		Registration: embedded.RegistrationConfig{Verification: authkit.RegistrationVerificationRequired},
		Keys:         embedded.KeysConfig{Path: "/vault/auth"}, // keys.json + totp.key; AllowEphemeralDevKeys only in dev
		TwoFactor:    embedded.TwoFactorConfig{Mode: authkit.TwoFactorOptional},
		Passkeys:     embedded.PasskeyConfig{RPID: "app.example.com", Origins: []string{"https://app.example.com"}},
		RBAC: []embedded.PersonaDef{{
			Name:   "org",
			Parent: authkit.RootPersona,
			Roles:  []embedded.RoleDef{{Name: "admin", Permissions: []string{"org:members:read", "org:members:manage"}}},
		}},
	}
	client, err := embedded.New(cfg, embedded.Deps{Postgres: pg, Redis: rdb, Email: mailer})
	if err != nil {
		return nil, err
	}
	srv, err := authhttp.New(client, authhttp.Config{
		TrustedProxies: []string{"10.0.0.0/8"}, // or DirectPeerIP: true when nothing sits in front
	})
	if err != nil {
		return nil, err
	}
	mount, err := authhttp.MountHandler(srv, authhttp.MountOptions{RefreshCookie: true})
	if err != nil {
		return nil, err
	}
	router := gin.New()
	router.NoRoute(authkitgin.Fallback(mount)) // host routes win; AuthKit answers the rest

	requireAuth := authkitgin.Required(srv.Verifier())
	orgScope := func(c *gin.Context) verify.PermissionScope {
		g, err := client.GroupInstanceForSlug(c.Request.Context(), authkit.GroupRef{Persona: "org", Instance: c.Param("org")})
		if err != nil {
			return verify.PermissionScope{} // an empty scope denies
		}
		return verify.PermissionScope{GroupID: g.ID, AuthorityIssuer: cfg.Token.Issuer, Persona: g.Persona, Instance: g.InstanceSlug}
	}
	router.GET("/api/v1/orgs/:org/members", requireAuth,
		authkitgin.RequirePermission(client, authkit.Perm("org:members:read"), orgScope),
		func(c *gin.Context) {
			claims, _ := authkitgin.UserClaims(c)
			c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID, "org": c.Param("org")})
		})
	return router, nil
}
```

`MountOptions`: `Groups` selects route groups (`auth`, `registration`,
`account`, `device_keys`, `admin`, `permission_groups`, `browser_oidc`,
`applications`, `delegated`, `documents`), `APIPrefix` anchors the API,
`ExcludeRoutes` drops routes the host shadows, `Wrap` decorates every route.
Non-gin hosts mount the handler like any `http.Handler`.

## Verification in a host

`srv.Verifier()` is a `*verify.Verifier`; `verify` imports no Postgres or
Redis, so a pure resource server depends on it alone.
`verify.Required`/`Optional` and the `authkitgin` twins put `verify.Claims` in
the request context. `RequirePermission` resolves the group name once and
authorizes the immutable UUID: a user is checked live against `GroupID`, a
group-bound API key must match the scope, an unbound delegated token is
authorized from its own `permissions`. `AuthorityIssuer` is this deployment's
`Token.Issuer`; `verify.PermissionScopeFromContext` hands the handler the
authorized scope.

## Surfaces

- `docs/api-endpoints.md` — generated route table plus wire notes; CI fails
  when stale.
- `docs/naming-policy.md` — user/group naming, renames and aliases.
- `SEMVER.md` — what the version contract covers.
- `SECURITY.md` — reporting and the CI gates.

## Refresh cookie

`MountOptions{RefreshCookie: true}` moves the rotating refresh token out of
every response body into an `HttpOnly`+`Secure`+`SameSite=Lax` cookie
(`authkit_rt`) path-scoped to the mount's `POST /token`, which takes the
body's `refresh_token` when present and the cookie otherwise. `DELETE /logout`
and a refresh failing with `user_banned` clear it; an unknown-token `401`
never does. A cookie-sourced refresh refuses a mismatched `Origin`. The SPA and
the mount must share an origin. Off by default.

## Browser OIDC

`GET /oidc/{provider}/login[?return_to=/app/path][&ui=popup&popup_nonce=…]`
→ provider → `/oidc/{provider}/callback` (GET, or POST for form_post) → `302`
to `Frontend.BaseURL + OIDCReturnPath` (default `/login/callback`):

- success: `#access_token=…&refresh_token=…&expires_in=…&provider=…[&return_to=…]`
  (no `refresh_token` with the refresh cookie);
- error: `#error=<code>&flow=login|link&provider=…`; `2fa_enrollment_required`
  carries `enrollment_token`, `enrollment_expires_in`, `allowed_methods`
  instead of an access token;
- popup: `postMessage` of `{type: "AUTHKIT_OIDC_RESULT", access_token, …, nonce}`
  or `{type: "AUTHKIT_OIDC_ERROR", error, flow, provider, nonce}`.

`return_to` must be app-relative. Linking a provider to an existing account is
`POST /api/v1/oidc/{provider}/link/start`: it needs fresh authentication
(`403 step_up_required`) and an existing link for the same issuer must be
unlinked first (`409 provider_change_requires_unlink`).

## RBAC

`Config.RBAC` is `[]embedded.PersonaDef`. Each persona is a permission
namespace (`org:members:read`) with a role catalog; non-root personas name one
`Parent`; `root` is the parentless singleton with AuthKit's built-in owner
role. `Capabilities` opt a persona into the generated
API-key, remote-application and custom-role routes; `Creation.Enabled` mounts
`POST /<persona>`. Assignments are rows keyed by persona and role name: treat
both as durable identifiers and never rename in place; removed names fail
closed without deleting rows. One role per subject per group; who may create a
group is the host's decision.

## Signed documents and delegated tokens

`documents.NewService` signs, persists and re-verifies an immutable JSON
envelope (`type`, `iss`, `aud`, opaque `payload`) with the engine's live key.
Pass it in `authhttp.Config.Documents`; `MountHandler` then serves
`GET|HEAD /.well-known/authkit/documents/{digest}` to the remote applications
pinned in `Config.Documents.Readers` (by id, proven domain or root-registered
issuer — never slug). Receivers use `documents.NewResolver` and
`verify.Verifier.VerifyDocument`.

`POST /api/v1/delegated/token` mounts when `Config.Delegated.Audiences` is set
and requires the one host seam:

```go
deps.DelegatedAuthorization = func(ctx context.Context, req authkit.DelegationRequest) (authkit.DelegationGrant, error) {
	if !mayDelegate(ctx, req.UserID, req.RequestedGrant) {
		return authkit.DelegationGrant{}, authkit.ErrDelegationRefused // 403 delegation_refused; any other error is 503
	}
	return authkit.DelegationGrant{Permissions: []string{"resource:read"}}, nil
}
```

The request `{audiences, ttl_seconds, delegate_certificate_der_b64url,
requested_grant}` is clamped to the configured audiences and TTL bounds;
AuthKit signs only the grant plus every published document digest, bound to
the delegate's leaf certificate as `cnf: {"x5t#S256": …}` (RFC 8705). A bound
token verifies only when `r.TLS.PeerCertificates[0]` hashes to that value —
terminate TLS on the resource server with
`tls.Config{ClientAuth: tls.RequestClientCert}` or stricter; anything else
fails `sender_proof_required`.

## Application self-registration

`Config.Applications = ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"}`
mounts `POST /api/v1/applications/register` `{"domain": "cozy.art"}`. The
server fetches `https://<domain>/.well-known/authkit/application.json`; that
fetch is the domain-control proof (https, no redirects, SSRF-guarded). The
document declares `issuer`, one of
`jwks_uri`/`public_keys`, and a requested `slug` (default: the hostname)
claimed like any org slug. The result is a `registered`-tier remote
application plus a service-owned `OrgPersona` group. Re-registering the same
domain re-proves the root and refreshes the keys — that is key rotation; a
keypair never rotates itself. `Deps.ApplicationAdmission` is the host's cost
gate.

## Device keys

`Config.DeviceKeys.Enabled` mounts `RouteDeviceKeys` for native clients.
`POST /api/v1/device-keys/enroll/begin` (email + public key → emailed code)
and `enroll/finish` (code + signature; an MFA-protected account must also
present its second factor) enrol a per-machine key. `login/begin` +
`login/finish` exchange a signed challenge for a short access token and
nothing else — no refresh session. `GET /api/v1/device-keys`,
`DELETE /api/v1/device-keys/{id}` and `POST /api/v1/device-keys/revoke-others`
manage keys; a revoked machine cannot revoke its replacement.

## Passkey primitives

`/api/v1/passkeys/*` covers browser login, registration and management. A host
that drives WebAuthn itself calls the same ceremonies on `*embedded.Client`;
every finish consumes its ceremony once and only for the purpose it was begun
with:

- `BeginDiscoverablePasskeyVerification` / `Finish…` → `VerifiedPasskey`, an
  identity proof only — no session, token or cookie;
- `BeginPasskeyAccount` / `Finish…` → a new passkey-only user (needs an open
  `Registration.NativeUserMode`);
- `BeginPasskeyRegistration(userID)`, then `FinishPasskeyRegistration` (add) or
  `FinishPasskeyReplacement` (atomic single-passkey rotate).

The host gates who may call these and never treats a `VerifiedPasskey` as a
session.

## Liveness

`verify.Required` is stateless: a banned or deleted user keeps a valid access
token until it expires (at most one access TTL). For a surface that cannot
accept that window:

```go
srv.Verifier().WithLiveness(client)
requiredLive, err := authkitgin.RequiredLive(srv.Verifier()) // verify.RequiredLive for net/http
```

It denies banned, deleted, reserved and unknown accounts on the next request
and hands the handler fresh `Username`/`Email`/`EmailVerified`. Fail-closed:
one `UserLivenessByIDs` read per request, no cache, a lookup error denies;
without `WithLiveness` construction returns `verify.ErrLivenessUnconfigured`.
