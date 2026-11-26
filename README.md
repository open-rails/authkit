# AuthKit

Stop paying for shitty SaaS pay-per-user auth services. Firebase would charge you $4,415 for 1 million monthly-active users; you can self-host that for free inside of the web-server you already run. It's simpler to run auth inside of your Go webserver's binary, in process, on your own Postgres (v18) database.

First install authkit into your Go project:

```sh
go get github.com/open-rails/authkit
```

Libraries and hosts that only need authentication or user-directory contracts import `github.com/open-rails/authkit/auth` and `github.com/open-rails/authkit/userinfo`. These packages use only the standard library and do not import or build AuthKit's service implementation. Custom host implementations can use their conformance tests. See [contract packages and migration](docs/contract-packages.md).

Apps of one business can share an account directory while other businesses
keep separate accounts in the same database. Use a stable tenant ID; see
[tenant directories, scoped permissions and migration](docs/tenant-directories.md).

Next let's build a client:

```go
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/adapters/smtp"
	"github.com/open-rails/authkit/adapters/twilio"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

func newAuth(ctx context.Context, db *pgxpool.Pool) (*authkit.Client, error) {
	cfg := authkit.Config{
		Database: authkit.DatabaseConfig{Schema: "profiles"}, // the Postgres schema AuthKit's tables go in
		// Who issues the JWTs users send back to prove who they are: that's you!
		// Every other URL derives from it (the API at https://myapp.com/auth/v1).
		Issuer: "https://myapp.com",

		HTTP: &authkit.HTTPConfig{
			DirectPeerIP: true, // no proxy in front; otherwise set TrustedProxies
			// Rate limits live in memory; set Deps.Redis when you run more than one copy of your server.
		},
		Roles: rbac, // See below for our RBAC system
	}

	// 1. Authkit needs to send verification and account recovery codes to emails and phone numbers.
	// Email goes through any SMTP server (SendGrid: smtp.sendgrid.net, username "apikey", an API key as password); texts through Twilio.
	port, _ := strconv.Atoi(os.Getenv("EMAIL_SMTP_PORT")) // 0 means 587
	email, err := smtp.New(smtp.Config{
		Server: smtp.Server{
			Host:     os.Getenv("EMAIL_SMTP_HOST"),
			Port:     port,
			Username: os.Getenv("EMAIL_SMTP_USERNAME"),
			Password: os.Getenv("EMAIL_SMTP_PASSWORD"),
			From:     "MyApp <hello@myapp.com>",
		},
		AppName: "MyApp",
	})
	if err != nil {
		return nil, err
	}
	sms, err := twilio.NewSMS(twilio.SMSConfig{
		AccountSID:          os.Getenv("TWILIO_ACCOUNT_SID"),
		AuthToken:           os.Getenv("TWILIO_AUTH_TOKEN"),
		MessagingServiceSID: os.Getenv("TWILIO_MESSAGING_SERVICE_SID"),
		AppName:             "MyApp",
	})
	if err != nil {
		return nil, err
	}

	// 2. Build the auth engine. It creates or upgrades its tables first; safe on every boot.
	return authkit.New(ctx, cfg, authkit.Deps{
		Postgres: db, // required: users, sessions and short-lived auth state
		// Signing keys come from /vault/auth/keys.json (and totp.key) unless
		// KeySource names another source, such as keys.Watch(dir, logger).
		Email: email, // sends verification codes, login codes and password resets
		SMS:   sms,   // same, for phone numbers
		// Both also report when they can't deliver, pausing that channel's sign-in until they can.
	})
}
```

Now let's make a shitty Reddit-clone. Oh wait; Reddit is already shit, I forgot lol.

First we need moderators; these are the unpaid neckbeards who enforce their arbitrary policies on users (plebians). Let's build that feature first:

```go
var (
	// This is a mutable object that we'll attach all of our personas, permissions, and roles onto.
	rbac = authkit.NewRoles()

	// Persona's are types of permission groups. root (the whole site) exists by default.
	// we'll have permission group per reddit-channel, like /c/golang
	Channel = rbac.Persona("channel")

	// Our own custom permissions, in addition to the ones that authkit includes automatically.
	PostsEdit     = Channel.Permission("posts", "edit")
	PostsDelete   = Channel.Permission("posts", "delete")
	PostsApprove  = Channel.Permission("posts", "approve")
	ChannelEdit   = Channel.Permission("self", "edit")   // change the channel's own data: its name, description and rules
	ChannelDelete = Channel.Permission("self", "delete") // delete the channel ("self" is just our name for the channel itself)

	// Roles are bundles of permissions, scoped to a specific persona.
	// There is always a singleton persona; root
	Moderator = Channel.Role("moderator", Channel.Resource("posts").All()) // edit, delete and approve posts
	Admin     = rbac.Root.Role("admin",
		Channel.All(),         // everything in every channel, deleting it included
		rbac.Root.Users.All(), // read, ban, delete and manage user accounts
	)
)
```

Permissions have 3 parts: `<persona>:<resource>:<action>` and they support wildcards like `channel:*` too. However, we use enums in code rather than strings, for type-safety.

AuthKit gives every persona these permissions for free, so you never define them yourself:

| Permission | Lets you |
|---|---|
| `channel:members:read` | see who holds which role in it |
| `channel:members:manage` | give someone a role, change it, or take it away |
| `channel:credentials:read`, `channel:credentials:manage` | list, or create and revoke, the channel's API keys and connected apps (only when `APIKeys` or `RemoteApplications` is on) |
| `channel:directory:read`, `channel:directory:manage` | read, or provision over SCIM, the channel's [directory](docs/scim.md#directory) of its connected apps' users (only when `RemoteApplications` is on) |

What a channel's data is, and who may change it, is define by your app. Authkit merely stores definitions for permissions and checks against those.

For the root persona (single-isntance only), they get these, defined by authkit:

| Permission | Lets you |
|---|---|
| `root:users:read` | look through users and their sign-in history |
| `root:users:ban` | ban and unban |
| `root:users:delete` | delete an account, or restore it within its 30 days |
| `root:users:manage` | edit someone else's account and sign them out everywhere |
| `root:users:invite` | invite someone to create an account |
| `root:tenants:read`, `root:tenants:manage` | look tenants up, or create and rename them |
| `root:members:read`, `root:members:manage` | see or hand out site-wide roles |

The only built-in role for every permission group is just `owner`. When owner is assigned to a user, that user automatically gets `<persona>:*` permissions, which is full permission over the entire channel, or root (entire site).

Now let's seed a reddit admin using `ADMIN_EMAIL`:

```go
func seed(ctx context.Context, auth *authkit.Client) (iam.User, error) {
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		return iam.User{}, errors.New("set ADMIN_EMAIL to the first admin's address")
	}
	// Creates the user if they don't exist, and grants them the admin role defined above
	return auth.EnsureUserRole(ctx, iam.RootGroup(), iam.UserByEmail(email), Admin)
}

// Our application-specific table
const channelsTable = `CREATE TABLE IF NOT EXISTS channels (
	name        text PRIMARY KEY,
	description text NOT NULL DEFAULT '',
	group_id    uuid NOT NULL UNIQUE
)`

var errChannelTaken = errors.New("that channel already exists")

// createChannel makes channel name, owned by ownerID: our row and AuthKit's permission group
// commit together or not at all.
func createChannel(ctx context.Context, db *pgxpool.Pool, auth *authkit.Client, name, ownerID string) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		owner := iam.UserSubject(ownerID)
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: Channel.Persona, Owner: &owner}, authkit.InTx(tx))
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO channels (name, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, name, g.ID)
		if err == nil && tag.RowsAffected() == 0 {
			err = errChannelTaken // rolling back takes the new group with it
		}
		return err
	})
}
```

Great. Now let's mount authkit's http handlers. This lets your end-users register and login.

```go
func main() { log.Fatal(run(context.Background())) }

func run(ctx context.Context) error {
	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	auth, err := newAuth(ctx, db)
	if err != nil {
		return err
	}
	defer auth.Close(context.Background())
	if err := auth.Start(ctx); err != nil { // background maintenance jobs
		return err
	}
	if _, err := db.Exec(ctx, channelsTable); err != nil { // our own table
		return err
	}
	admin, err := seed(ctx, auth)
	if err != nil {
		return err
	}
	// Our admin opens /c/announcements; later boots find it already made.
	if err := createChannel(ctx, db, auth, "announcements", admin.ID); err != nil && !errors.Is(err, errChannelTaken) {
		return err
	}

	// Mount all gin routes
	r := gin.Default()
	if err := authkitgin.Mount(r, auth); err != nil {
		return err
	}
	mountForum(r, auth, db)

	return r.Run(":8080")
}
```

Mounting gives your users the routes below under `/auth/v1`, plus the public keys that let anyone verify AuthKit's tokens. Every request and response shape is in [`api/openapi.json`](api/openapi.json), generated from the route catalog.

**Signing up and signing in** (every sign-in answers an `AuthResult`: signed in, or the one next step, such as a second factor)

| Route | What it does |
|---|---|
| `POST /auth/v1/register` | create an account |
| `GET /auth/v1/register/availability` | validate a registration username and its availability; never answers for an email or phone number |
| `GET /auth/v1/usernames/availability` | validate username syntax and availability, including on sites with closed registration |
| `GET /auth/v1/usernames/generate` | one available generated username; not a reservation |
| `POST /auth/v1/register/abandon` | cancel a sign-up that was never confirmed |
| `POST /auth/v1/verify/request` | send a code or link to prove an email or phone |
| `POST /auth/v1/verify/confirm` | prove it |
| `POST /auth/v1/password/login` | sign in with a password |
| `POST /auth/v1/password/reset/request` | send a "forgot password" link |
| `POST /auth/v1/password/reset/confirm` | set a new password with that link |
| `POST /auth/v1/passkeys/login/begin`, `/finish` | sign in with a passkey |
| `POST /auth/v1/2fa/challenge` | send the second-factor code to another of your factors |
| `POST /auth/v1/2fa/verify` | finish signing in with it |
| `POST /auth/v1/device-verification/confirm`, `/send` | finish signing in on a new device with the code sent to the account's owner, or send it again |
| `POST /auth/v1/account/recovery/confirm` | undo deleting your own account, within 30 days, and go on signing in |
| `POST /auth/v1/invitations/redeem` | accept an invitation |

Sign-ins are limited per device over 24 hours: 5 accounts per browser (20 per address for a client without AuthKit's device cookie), and 10 new devices per account. Signing back into a counted account, or from a device the account used in the last 30 days, is never limited by these counts. Failed passwords are also limited per identifier (`password_login_identifier`, see [HTTP](docs/http.md#client-addresses-and-rate-limits)). Past the device limit, a new device enters a code sent to the owner's email or phone, which a posted password doesn't get you.

With `iam.RoutePasswordless` in `HTTP.Groups`, people sign in contact-first: an email or phone, then the 6-digit code sent there, confirmed with the challenge its start answered, or a passkey (the routes `/passwordless/start` and `/confirm`). Nobody else's starts or wrong guesses spend that code ([HTTP](docs/http.md#client-addresses-and-rate-limits)). Unless `Registration` is `closed`, proving a new contact there signs it up (`invite_only` needs an invitation); with a `SignUp` agreement, that sign-up, like every other, first accepts your terms (`agreement_required` names them, and the code stays good for the retry). An account whose only proof is a phone proves it again on every new device. Text messages go only to `SMSCountries` and numbers a person texts from, and pass send limits per number, account, address, country, number range and client; with `Deps.Captcha` (Turnstile or hCaptcha) a code start needs a solved challenge. Each code ends with an origin-bound line (`@example.com #123456`) so browsers autofill it only on your site. See [identity](docs/identity.md#network-accounts).

**MFA upgrades after promotion**

Granting an MFA-protected role succeeds before its recipient enrolls. AuthKit
requires setup on the next sign-in or authenticated visit, and blocks protected
access until it is complete. Administrators can also set an individual
requirement with `UpdateUser(..., iam.UserUpdate{MFARequired: &required})` or
`PATCH /auth/v1/admin/users/{user_id}` with `{"mfa_required":true}`. Clearing that
flag does not bypass role or deployment policy. The shared user editor and
sign-in UI support this flow, including fresh sign-in when an old session cannot
safely enroll a new factor. See [the MFA policy guide](docs/rbac.md#requiring-mfa-after-a-promotion).

**Sessions and tokens**

| Route | What it does |
|---|---|
| `POST /auth/v1/token` | trade a refresh token for fresh tokens |
| `DELETE /auth/v1/logout` | sign out |
| `POST /auth/v1/me/step-up/password`, `/2fa`, `/code`, `/passkey` | prove it's really you before a sensitive change: your password, second factor, a code to your email or phone, or a passkey |
| `POST /auth/v1/me/step-up/2fa/send` | send that second-factor code |
| `POST /auth/v1/me/step-up/code/send` | send a code to your proven email or phone |
| `POST /auth/v1/me/step-up/passkey/begin` | start a passkey step-up |
| `GET /auth/v1/me/sessions` | your signed-in devices |
| `DELETE /auth/v1/me/sessions` | sign out everywhere else |
| `DELETE /auth/v1/me/sessions/{id}` | sign out one device |
| `GET /auth/v1/me/session-events` | your sign-in history |
| `GET /.well-known/jwks.json` | public keys for checking AuthKit's tokens |

**Your own account**

| Route | What it does |
|---|---|
| `GET /auth/v1/me` | who you are |
| `PATCH /auth/v1/me` | change your username or language |
| `DELETE /auth/v1/me` | delete your account (30 days to change your mind) |
| `GET /auth/v1/me/security` | whether you need to step up and how, and your second factors |
| `GET /auth/v1/me/agreements` | the terms and policies you accepted, and any due now |
| `POST /auth/v1/me/agreements` | accept them |
| `PUT /auth/v1/me/password` | change your password |
| `PUT /auth/v1/me/email` | change your email (a code goes to the new one) |
| `PUT /auth/v1/me/phone` | change your phone number |
| `DELETE /auth/v1/me/phone` | remove it |
| `DELETE /auth/v1/me/providers/{provider}` | unlink a sign-in provider |
| `GET /auth/v1/me/groups` | the groups you hold a role in |
| `GET /auth/v1/me/permissions` | your role and permissions in one group (`?group_id=`) |
| `GET /auth/v1/users` | anyone's public profile (`?ids=` or `?username=`), no sign-in needed |
| `GET /auth/v1/capabilities` | what this server offers, for your UI |
| `GET /auth/v1/events` | retained events in an authorized tenant or authority scope; readers keep their own cursor |

**Two-factor, passkeys and device keys**

| Route | What it does |
|---|---|
| `POST /auth/v1/me/2fa/setup` | start adding one: a code to your phone, or an authenticator app's secret |
| `POST /auth/v1/me/2fa/factors` | add it with that code |
| `PATCH /auth/v1/me/2fa/factors/{id}` | make it your default |
| `DELETE /auth/v1/me/2fa/factors/{id}` | remove it |
| `DELETE /auth/v1/me/2fa` | turn two-factor off |
| `POST /auth/v1/me/2fa/backup-codes` | new backup codes |
| `GET /auth/v1/me/sign-in-keys` | your passkeys and device keys |
| `PATCH /auth/v1/me/sign-in-keys/{id}` | rename one |
| `DELETE /auth/v1/me/sign-in-keys/{id}` | revoke one |
| `POST /auth/v1/me/passkeys/register/begin`, `/finish` | add a passkey after step-up |
| `POST /auth/v1/me/passkeys/enroll/begin`, `/finish` | use a restricted enrollment token to create the first passkey and complete mandatory MFA sign-in |

Passkeys on a platform authenticator or FIDO2 security key require PIN/biometric
user verification on every creation and assertion. A verified passkey sign-in
already supplies MFA; it needs no extra password or OTP. Presence-only key touch
does not qualify. See the [FIDO passkey guidance](https://fidoalliance.org/passkeys/).
The shared `SignInKeysPanel` manages keys, and required-enrollment UI offers a
passkey alongside TOTP and available SMS. Code factors remain a separate store;
`GET /me/security` reports `passkeys_enrolled` as well as their status.

Required MFA accepts configured TOTP/SMS, UV passkeys, or a backup-code second
proof after a primary sign-in. Email alone is not privileged MFA. Delivery
outages do not erase enrollment or authorize password-only replacement.
Existing passkeys protect the account across RPs, though each browser ceremony
is bound to its own RP/origin. Register another app's key from an already-MFA
session; a password cannot enroll over an established key on another RP.

An emailed password reset on a verified account preserves its factors and
passkeys, issues no session, and still requires MFA at sign-in. First contact
proof for an unproven registration instead retires the claimant's credentials.
Passkey-only accounts can generate or replace backup codes after strong
step-up. A valid primary sign-in plus one backup code recovers access when a
key is unavailable; the code alone never signs in. Codes remain hashed and
single-use, are replaced atomically, and disappear with the last factor/key.
Upgrading legacy email-only enrollment to its first required passkey retires
the old recovery set; generate a new set from the UV-proven session. Removing a required last strong factor/key is refused;
adding a verified replacement first permits removing the old factor.

**Groups** (each channel's permission group; `root` is the site-wide group, where roles like `root:admin` live)

| Route | What it does |
|---|---|
| `GET /auth/v1/groups/{group_id}/members` | who holds which role (`?expand=user` adds their public profiles) |
| `PUT /auth/v1/groups/{group_id}/members/{kind}/{id}` | give someone a role, or change it (`{kind}` is `users`) |
| `DELETE /auth/v1/groups/{group_id}/members/{kind}/{id}` | take their role away |
| `GET /auth/v1/groups/{group_id}/roles` | the roles this group has |
| `GET /auth/v1/groups/{group_id}/roles/{role}` | one of them, and what it grants |
| `GET /auth/v1/groups/{group_id}/invitations` | its invitations |
| `POST /auth/v1/groups/{group_id}/invitations` | invite someone with a link, or by email |
| `DELETE /auth/v1/groups/{group_id}/invitations/{id}` | revoke one |

**Site admins** (need the matching `root:` permission, and a recent sign-in for account changes; staff change only accounts they outrank, so demote a peer first. Bans, deletions, sign-outs and contact changes are recorded with who made them in `Client.ListEvents`, for your audit log.)

| Route | What it does |
|---|---|
| `GET /auth/v1/admin/users` | look through users |
| `GET /auth/v1/admin/users/{user_id}` | one user |
| `PATCH /auth/v1/admin/users/{user_id}` | edit their account |
| `PUT /auth/v1/admin/users/{user_id}/ban` | ban them, until a time or for good |
| `DELETE /auth/v1/admin/users/{user_id}/ban` | lift the ban |
| `DELETE /auth/v1/admin/users/{user_id}` | delete an account |
| `POST /auth/v1/admin/users/{user_id}/restore` | restore it within 30 days |
| `GET /auth/v1/admin/users/{user_id}/sessions` | their signed-in devices |
| `DELETE /auth/v1/admin/users/{user_id}/sessions` | sign them out everywhere |
| `GET /auth/v1/admin/users/{user_id}/session-events` | their sign-in history |
| `GET /auth/v1/admin/provisioning/targets` | how each [SCIM](docs/scim.md) target's sync is doing |
| `POST /auth/v1/admin/tenants` | create a tenant: its UUID and name (`root:tenants:manage`) |
| `GET /auth/v1/admin/tenants/{tenant_id}` | one tenant (`root:tenants:read`) |
| `PATCH /auth/v1/admin/tenants/{tenant_id}` | [rename](docs/tenant-directories.md#tenant-names) it (`root:tenants:manage`) |
| `GET /auth/v1/admin/tenants/by-slug/{slug}` | the tenant a current or former name belongs to (`root:tenants:read`) |

Switch on social logins (Google, Apple, GitHub, Discord) or API keys, and AuthKit mounts their routes too. Passwordless sign-in, device keys and personal access tokens are opt-in route groups: add `iam.RoutePasswordless`, `iam.RouteDeviceKeys` or `iam.RoutePersonalAccessTokens` to `HTTP.Groups` (nil is `iam.DefaultRouteGroups()`). Leave `iam.RouteInvitations` out, and the invitation routes go.

Group API keys belong to the organization; their creator is audit information. Optional [personal access tokens](docs/personal-access-tokens.md) are a separate, user-owned credential, on only with `iam.RoutePersonalAccessTokens`.

Now for our application-specific routes, we can check user permissions using middleware, to enforce that certain actions are moderator or admin-only:

```go
func mountForum(r *gin.Engine, auth *authkit.Client, db *pgxpool.Pool) {
	f := &forum{auth: auth, db: db, posts: map[int]*Post{}}
	signedIn := authkitgin.Required(auth)

	r.GET("/c", f.listChannels)             // anyone can browse the channels
	r.POST("/c", signedIn, f.createChannel) // anyone signed in can start a channel

	ch := r.Group("/c/:channel", f.channel)   // every route below knows its channel
	ch.GET("", f.getChannel)                  // anyone can read a channel's page
	ch.GET("/posts", f.listPosts(true))       // anyone can read
	ch.POST("/posts", signedIn, f.createPost) // anyone signed in can post

	// moderator-specific routes:
	ch.GET("/queue", authkitgin.RequirePermission(auth, PostsApprove), f.listPosts(false))         // see pending posts
	ch.PATCH("/posts/:id", authkitgin.RequirePermission(auth, PostsEdit), f.editPost)              // edit a post
	ch.DELETE("/posts/:id", authkitgin.RequirePermission(auth, PostsDelete), f.deletePost)         // delete a post
	ch.POST("/posts/:id/approve", authkitgin.RequirePermission(auth, PostsApprove), f.approvePost) // approve / disapprove posts

	// admin-specific routes:
	ch.PUT("/moderators/:user_id", signedIn, f.appoint)                               // appoint a moderator
	ch.DELETE("/moderators/:user_id", signedIn, f.appoint)                            // remove a moderator
	ch.PATCH("", authkitgin.RequirePermission(auth, ChannelEdit), f.editChannel)      // edit channel settings
	ch.DELETE("", authkitgin.RequirePermission(auth, ChannelDelete), f.deleteChannel) // delete channel
}
```

The rest is ordinary app code (our channel and post handlers), not AuthKit. The whole program is one file: [examples/reddit/main.go](examples/reddit/main.go).

For groups declared by application configuration, an explicit migration command
can call `authkit.EnsureGroups(ctx, pool, cfg, groups, logger)` after `authkit.Migrate`.
Supply the usual database, roles and tenancy in `cfg`, and stable IDs in
`[]iam.NewGroup`. It creates missing ownerless groups without an AuthKit runtime,
signing keys, senders or workers. Existing live groups and their assignments stay
unchanged; deleted groups and conflicting tenants/personas are refused. Each
group and its event commit together; after an interrupted batch, repeat the same
input. Assign users through the normal client separately. ContentKit's configured
channel provisioning uses this operation through its AuthKit migration adapter.

Account deletion uses one `authkit_account_delete_due` batch job per issuer, scheduled at the earliest deletion's `purge_at`, rather than a future River job per account. The 30-day recovery deadline remains authoritative; issuer cleanup callbacks must finish before the account row is removed. See [account deletion](docs/identity.md) for timing.

`Start` runs AuthKit's background jobs (account deletion, events, cleanup) on its own [River](https://riverqueue.com) client in `Config.Database.RiverSchema` (default `Config.Database.Schema`), whose tables `New` creates. An app that already runs a River fleet builds it in that schema with `riverhelpers.New(ctx, db, riverConfig, auth.RiverJobs(), …)` (`github.com/open-rails/helpers/river`) and calls `auth.Start(ctx, authkit.WithRiverClient(fleet))` instead; the app starts and stops that fleet, and `auth.Close` leaves it running. AuthKit's own client takes a pool of `Config.Database.RiverConns` connections (default 5), copied from `Deps.Postgres`, beside the main pool (`Deps.Postgres`'s size) and an ephemeral one (a quarter of it, at least 2): a host that budgets its PostgreSQL connections counts all three. Behind PgBouncer in transaction mode, `Deps.PostgresSession` names the direct connection for migrations, `LISTEN` and session locks: see [PostgreSQL and PgBouncer](docs/postgres.md).

`New` fails only when AuthKit can't run safely: PostgreSQL still unreachable after 30 seconds (or `ctx`), migrations failing, no usable signing key, or configuration it can't read without weakening auth. A misconfigured or unreachable optional dependency switches off only what needs it: an identity provider is disabled (its sign-ins answer `provider_unavailable`), a remote application's tokens are refused, email flows answer `email_unavailable`, and limits stay per process while Redis is down. `auth.Ready(ctx)` is the readiness check (PostgreSQL, River, signing key); `auth.Probes()` lists the optional dependencies and degraded features for your dependency supervisor, none of which fails readiness.

A service whose callers sign in elsewhere sets `Config.Resource`: `auth.Authenticator()` then also admits the access tokens its trusted issuers mint for it, bound to their group ([resource server](docs/resource-server.md)). Every session this instance issues its own users is DPoP-bound. That never changes how tokens are validated: a bound token needs its proof, an unbound token is a bearer token, whoever issued it.

More: [resource server](docs/resource-server.md), [keys](docs/keys.md), [PostgreSQL and PgBouncer](docs/postgres.md), [tokens](docs/tokens.md), [SCIM provisioning and user info](docs/scim.md), [subject, invoker, credential](docs/identity.md), [HTTP](docs/http.md), [RBAC](docs/rbac.md), [security](SECURITY.md), [v1 stability](docs/stability.md)

Contributing: changes go to the open release candidate named in [OPEN.md](OPEN.md), not to master ([branches and CI](docs/ci.md)).

See [the retained event log](docs/event-log.md) for native and HTTP readers and independent cursors.
