# AuthKit

Stop paying for shitty SaaS pay-per-user auth services. Firebase would charge you $4,415 for 1 million monthly-active users; you can self-host that for free inside of the web-server you already run. It's simpler to run auth inside of your Go webserver's binary, in process, on your own Postgres (v18) database.

First install authkit into your Go project:

```sh
go get github.com/open-rails/authkit
```

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
	twilioemail "github.com/open-rails/authkit/adapters/twilio/email"
	twiliosms "github.com/open-rails/authkit/adapters/twilio/sms"
	"github.com/open-rails/authkit/iam"
)

func newAuth(ctx context.Context, db *pgxpool.Pool) (*authkit.Auth, error) {
	// 1. Create or upgrade AuthKit's tables. Safe to run on every boot.
	err := authkit.Migrate(
		ctx,
		db, // your Postgres pool
		authkit.MigrateOptions{Schema: "profiles"}, // schema where Authkit's tables will go
	)
	if err != nil {
		return nil, err
	}

	// 2. Authkit needs to send verification and account recovery codes to emails and phone numbers.
	// Configure your messaging provider (Twilio) here.
	mailer, err := twilioemail.New(twilioemail.Config{
		APIKey:    os.Getenv("SENDGRID_API_KEY"),
		FromEmail: "hello@myapp.com",
		AppName:   "MyApp",
	})
	if err != nil {
		return nil, err
	}
	texter, err := twiliosms.New(twiliosms.Config{
		AccountSID:          os.Getenv("TWILIO_ACCOUNT_SID"),
		AuthToken:           os.Getenv("TWILIO_AUTH_TOKEN"),
		MessagingServiceSID: os.Getenv("TWILIO_MESSAGING_SERVICE_SID"),
		AppName:             "MyApp",
	})
	if err != nil {
		return nil, err
	}

	// 3. Build the auth engine.
	return authkit.New(
		ctx,
		authkit.Config{
			// Configure JWTs; authkit issues these to users; users then send them back with requests to prove who they are!
			Token: authkit.TokenConfig{
				Issuer:          "https://myapp.com", // who issued this; that's you!
				IssuedAudiences: []string{"myapp"},   // who this JWT is intended for (doesn't have to be yourself, but usually is)
			},
			Keys: authkit.KeysConfig{
				Path: "/vault/auth", // where your signing keys are stored; a keys.json file
			},
			HTTP: authkit.HTTPConfig{
				DirectPeerIP: true, // no proxy in front; otherwise set TrustedProxies
				// Rate limits live in memory; set Redis when you run more than one copy of your server.
			},
			Roles: roles, // See below for our RBAC system
		},
		authkit.Deps{
			Postgres: db,     // required: users, sessions and short-lived auth state
			Email:    mailer, // sends verification codes, login codes and password resets
			SMS:      texter, // same, for phone numbers
		},
	)
}
```

Now let's make a shitty Reddit-clone. Oh wait; Reddit is already shit, I forgot lol.

First we need moderators; these are the unpaid neckbeards who enforce their arbitrary policies on users (plebians). Let's build that feature first:

```go
var roles = authkit.RoleConfig{
	// Persona's are types of permission groups. root (the whole site) exists by default.
	Personas: map[string]authkit.Persona{
		// we'll have permission group per reddit-channel, like /c/golang
		"channel": {
			// Our own custom permissions, in addition to the ones that authkit includes automatically.
			Permissions: []string{
				"channel:posts:edit", "channel:posts:delete", "channel:posts:approve",
				"channel:self:edit",   // change the channel's own data: its name, description and rules
				"channel:self:delete", // delete the channel ("self" is just our name for the channel itself)
			},
		},
	},
	// Roles are bundles of permissions, scoped to a specific persona.
	// There is always a singleton persona; root
	Roles: []authkit.Role{
		{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}}, // edit, delete and approve posts
		{Persona: iam.RootPersona, Name: "admin", Permissions: []string{
			"channel:*",    // everything in every channel, deleting it included
			"root:users:*", // read, ban, delete and manage user accounts
		}},
	},
}
```

Permissions have 3 parts: `<persona>:<resource>:<action>` and they support wildcards like `channel:*` too.

AuthKit gives every persona these permissions for free, so you never list them yourself:

| Permission | Lets you |
|---|---|
| `channel:members:read` | see who holds which role in it |
| `channel:members:manage` | give someone a role, change it, or take it away |
| `channel:roles:manage` | define the channel's own custom roles (only when `CustomRoles` is on) |
| `channel:credentials:read`, `channel:credentials:manage` | list, or create and revoke, the channel's API keys and connected apps (only when `APIKeys` or `RemoteApplications` is on) |

What a channel's data is, and who may change it, is define by your app. Authkit merely stores definitions for permissions and checks against those.

For the root persona (single-isntance only), they get these, defined by authkit:

| Permission | Lets you |
|---|---|
| `root:users:read` | look through users and their sign-in history |
| `root:users:ban` | ban and unban |
| `root:users:delete` | delete an account, or restore it within its 30 days |
| `root:users:manage` | edit someone else's account and sign them out everywhere |
| `root:users:invite` | invite someone to create an account |
| `root:members:read`, `root:members:manage` | see or hand out site-wide roles |

The only built-in role for every permission group is just `owner`. When owner is assigned to a user, that user automatically gets `<persona>:*` permissions, which is full permission over the entire channel, or root (entire site).

Now let's seed a reddit admin using `ADMIN_EMAIL`:

```go
func seed(ctx context.Context, auth *authkit.Auth) (iam.User, error) {
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		return iam.User{}, errors.New("set ADMIN_EMAIL to the first admin's address")
	}
	// Creates the user if they don't exist, and grants them the admin role defined above
	return auth.EnsureUserRole(ctx, iam.UserByEmail(email), iam.RootGroup(), "admin")
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
func createChannel(ctx context.Context, db *pgxpool.Pool, auth *authkit.Auth, name, ownerID string) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		owner := iam.UserSubject(ownerID)
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: "channel", Owner: &owner}, authkit.InTx(tx))
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
	defer auth.Close()
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

Mounting gives your users all of this: 59 routes under `/api/v1`, plus the public keys that let anyone check AuthKit's tokens.

**Signing up and signing in**

| Route | What it does |
|---|---|
| `POST /api/v1/register` | create an account |
| `GET /api/v1/register/availability` | is this username free? |
| `POST /api/v1/register/abandon` | cancel a sign-up that was never confirmed |
| `POST /api/v1/verify/request` | send a code or link to an email or phone |
| `POST /api/v1/verify/confirm` | prove the code or link |
| `POST /api/v1/password/login` | sign in with a password |
| `POST /api/v1/password/reset/request` | send a "forgot password" link |
| `POST /api/v1/password/reset/confirm` | set a new password with that link |
| `POST /api/v1/passkeys/login/begin`, `/finish` | sign in with a passkey |
| `POST /api/v1/2fa/challenge` | send the second-factor code during sign-in |
| `POST /api/v1/2fa/verify` | finish signing in with it |
| `POST /api/v1/account/recovery/confirm` | undo deleting your own account, within 30 days |
| `POST /api/v1/invites/redeem` | accept an invitation |

**Sessions and tokens**

| Route | What it does |
|---|---|
| `POST /api/v1/token` | trade a refresh token for fresh tokens |
| `DELETE /api/v1/logout` | sign out |
| `POST /api/v1/step-up/password`, `/2fa` | prove it's really you before a sensitive change |
| `GET /api/v1/user/sessions` | your signed-in devices |
| `DELETE /api/v1/user/sessions` | sign out everywhere else |
| `DELETE /api/v1/user/sessions/{id}` | sign out one device |
| `GET /.well-known/jwks.json` | public keys for checking AuthKit's tokens |

**Your own account**

| Route | What it does |
|---|---|
| `GET /api/v1/me` | who you are |
| `GET /api/v1/me/groups` | the groups you hold a role in |
| `GET /api/v1/me/permissions` | your permissions in one group (`?group_id=`) |
| `PATCH /api/v1/user/username` | change your username |
| `PATCH /api/v1/user/preferred-language` | change your language |
| `POST /api/v1/user/password` | change your password |
| `DELETE /api/v1/user/providers/{provider}` | unlink a sign-in provider |
| `DELETE /api/v1/user` | delete your account (30 days to change your mind) |
| `GET /api/v1/capabilities` | what this server offers, for your UI |

**Two-factor and passkeys**

| Route | What it does |
|---|---|
| `GET /api/v1/user/2fa` | your two-factor settings |
| `POST /api/v1/user/2fa` | turn on two-factor, or add a factor |
| `DELETE /api/v1/user/2fa` | turn it off |
| `POST /api/v1/user/2fa/backup-codes` | new backup codes |
| `GET /api/v1/passkeys` | your passkeys |
| `POST /api/v1/passkeys/register/begin`, `/finish` | add a passkey |
| `PATCH /api/v1/passkeys/{id}` | rename one |
| `DELETE /api/v1/passkeys/{id}` | remove one |

**Groups** (each channel's permission group)

| Route | What it does |
|---|---|
| `GET /api/v1/groups/{group_id}/members` | who holds which role |
| `POST /api/v1/groups/{group_id}/members` | add someone (by email, it sends an invitation) |
| `PUT /api/v1/groups/{group_id}/members/{user}/roles/{role}` | give someone a role, or change it |
| `DELETE /api/v1/groups/{group_id}/members/{user}` | take their role away |
| `GET /api/v1/groups/{group_id}/roles` | the roles this group has |
| `GET /api/v1/groups/{group_id}/invites/links` | its invite links |
| `POST /api/v1/groups/{group_id}/invites/links` | make an invite link that grants a role |
| `DELETE /api/v1/groups/{group_id}/invites/links/{link}` | revoke one |

**Site admins** (need the matching `root:` permission)

| Route | What it does |
|---|---|
| `GET /api/v1/admin/users` | look through users |
| `GET /api/v1/admin/users/{user_id}` | one user |
| `GET /api/v1/admin/users/{user_id}/signins` | their sign-in history |
| `POST /api/v1/admin/users/{user_id}/ban`, `/unban` | ban or unban |
| `DELETE /api/v1/admin/users/{user_id}` | delete an account |
| `POST /api/v1/admin/users/{user_id}/restore` | restore it within 30 days |
| `POST /api/v1/admin/users/{user_id}/sessions/revoke` | sign them out everywhere |
| `GET /api/v1/admin/roles` | who holds site-wide roles |
| `PUT /api/v1/admin/users/{user_id}/roles/{role}` | give a site-wide role, like `admin` |
| `DELETE /api/v1/admin/users/{user_id}/roles/{role}` | take it away |

Switch on social logins (Google, Apple, GitHub, Discord), API keys or custom roles, and AuthKit mounts their routes too.

Now for our application-specific routes, we can check user permissions using middleware, to enforce that certain actions are moderator or admin-only:

```go
func mountForum(r *gin.Engine, auth *authkit.Auth, db *pgxpool.Pool) {
	f := &forum{auth: auth, db: db, posts: map[int]*Post{}}
	signedIn := authkitgin.Required(auth.Verifier())

	// may signs the person in, then asks AuthKit: do they hold perm in the channel from the URL?
	may := func(perm iam.Perm) gin.HandlerFunc {
		return authkitgin.RequirePermission(auth, perm, func(c *gin.Context) iam.GroupRef {
			return iam.GroupByID(c.GetString("channel"))
		})
	}

	r.GET("/c", f.listChannels)             // anyone can browse the channels
	r.POST("/c", signedIn, f.createChannel) // anyone signed in can start a channel

	ch := r.Group("/c/:channel", f.channel)   // every route below knows its channel
	ch.GET("", f.getChannel)                  // anyone can read a channel's page
	ch.GET("/posts", f.listPosts(true))       // anyone can read
	ch.POST("/posts", signedIn, f.createPost) // anyone signed in can post

	// moderator-specific routes:
	ch.GET("/queue", may("channel:posts:approve"), f.listPosts(false))         // see pending posts
	ch.PATCH("/posts/:id", may("channel:posts:edit"), f.editPost)              // edit a post
	ch.DELETE("/posts/:id", may("channel:posts:delete"), f.deletePost)         // delete a post
	ch.POST("/posts/:id/approve", may("channel:posts:approve"), f.approvePost) // approve / disapprove posts

	// admin-specific routes:
	ch.PUT("/moderators/:user_id", signedIn, f.appoint)        // appoint a moderator
	ch.DELETE("/moderators/:user_id", signedIn, f.appoint)     // remove a moderator
	ch.PATCH("", may("channel:self:edit"), f.editChannel)      // edit channel settings
	ch.DELETE("", may("channel:self:delete"), f.deleteChannel) // delete channel
}
```

The rest is ordinary app code (our channel and post handlers), not AuthKit. The whole program is one file: [examples/reddit/main.go](examples/reddit/main.go).

More: [routes](docs/api-endpoints.md) · [tokens and claims](docs/verification.md) · [rate limits](docs/security/rate-limits.md) · [keys.json](jwtkit/KEY_ROTATION.md)
