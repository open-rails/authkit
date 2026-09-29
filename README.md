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
			Roles: roles, // who may do what; see below
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
	// Persona's are a type of permission group. root (the whole site) always exists.
	Personas: map[string]authkit.Persona{
		// we'll create one permission group per reddit-channel, like /c/golang
		"channel": {
			// Our own permissions. Every persona also gets AuthKit's built-ins for free:
			// channel:self:* (read, update, delete the channel), channel:members:*, channel:roles:manage
			// and channel:credentials:* (its API keys and apps, when switched on).
			Permissions: []string{"channel:posts:edit", "channel:posts:delete", "channel:posts:approve"},
			// Anyone signed in may start a channel and becomes its owner. Only admins may take /c/announcements.
			Creation: authkit.GroupCreation{Enabled: true, ReservedSlugs: []string{"announcements"}},
		},
	},
	// Roles are bundles of permissions, scoped to a specific persona.
	// There is always a singleton persona; root
	Roles: []authkit.Role{
		{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}}, // edit, delete and approve posts
		{Persona: iam.RootPersona, Name: "admin", Permissions: []string{
			"channel:*",    // read, edit, and delete any channel
			"root:users:*", // read, ban, delete and manage user accounts
		}},
	},
}
```

Permissions have 3 parts: `<persona>:<resource>:<action>` and they support wildcards like `channel:*` too.

AuthKit gives every persona these permissions for free, so you never list them yourself:

| Permission | Lets you |
|---|---|
| `channel:self:read` | see the channel's settings: its id, name and rename history |
| `channel:self:update` | rename it or change its display name |
| `channel:self:delete` | delete it |
| `channel:members:read` | see who holds which role in it |
| `channel:members:manage` | give someone a role, change it, or take it away |
| `channel:roles:manage` | define the channel's own custom roles (only when `CustomRoles` is on) |
| `channel:credentials:read`, `channel:credentials:manage` | list, or create and revoke, the channel's API keys and connected apps (only when `APIKeys` or `RemoteApplications` is on) |

The root group has its own:

| Permission | Lets you |
|---|---|
| `root:users:read` | look through users and their sign-in history |
| `root:users:ban` | ban and unban |
| `root:users:delete` | delete an account, or restore it within its 30 days |
| `root:users:manage` | edit someone else's account and sign them out everywhere |
| `root:users:invite` | invite someone to create an account |
| `root:members:read`, `root:members:manage` | see or hand out site-wide roles |

It has no `self`, because nobody renames or deletes the whole site.

A channel's members are the people who hold a role there: its owner and moderators. Readers and posters don't need to be members; who may post is your app's call.

On every boot, AuthKit makes sure `ADMIN_EMAIL` is one. If there's no such account yet, AuthKit makes one with no password, and its owner signs in with "forgot password".

Channels are data, not config: they're made while the site runs. People make them with AuthKit's own route, `POST /api/v1/channel` with `{"slug": "golang"}`, and become that channel's owner. Code makes them with `CreateGroup`. Here our admin opens /c/announcements, a name only admins may take.

```go
func seed(ctx context.Context, auth *authkit.Auth) error {
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		return errors.New("set ADMIN_EMAIL to the first admin's address")
	}
	// The operator is your own code, trusted to do anything.
	admin, err := auth.EnsureUserRole(ctx, iam.OperatorActor(), iam.RootGroup(), iam.UserByEmail(email), "admin")
	if err != nil {
		return err
	}
	// Acting as the admin now. Later boots find the channel already made.
	_, _, err = auth.CreateGroup(ctx, iam.UserActor(admin.ID), iam.NewGroup{Persona: "channel", Slug: "announcements"})
	return err
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
	if err := seed(ctx, auth); err != nil {
		return err
	}
	r := gin.Default()
	if err := authkitgin.Mount(r, auth); err != nil { // /api/v1/*, /.well-known/jwks.json, /oidc/*
		return err
	}
	mountForum(r, auth)
	return r.Run(":8080")
}
```

Admins can already look after people with AuthKit's own routes: `GET /api/v1/admin/users` to see everyone, and `POST /api/v1/admin/users/{user_id}/ban` (or `/unban`). The admin's `root:users:*` opens those doors.

Badges are handed out per channel, too. Bob can moderate /c/golang and nowhere else. The owner of /c/golang, or any admin, pins the badge on him with `PUT /c/golang/moderators/{bob's user id}`; AuthKit's own `PUT /api/v1/channel/golang/members/{user_id}/roles/moderator` does the same. Then every forum route asks AuthKit about the channel in its URL. Bob gets in at /c/golang and is turned away at /c/rust, while admins get in everywhere. Roles are checked live, so a badge taken away stops working right away.

```go
func mountForum(r *gin.Engine, auth *authkit.Auth) {
	f := &forum{auth: auth, posts: map[int]*Post{}}
	signedIn := authkitgin.Required(auth.Verifier())
	// may signs the person in, then asks AuthKit: do they hold perm in the channel from the URL?
	may := func(perm iam.Perm) gin.HandlerFunc {
		return authkitgin.RequirePermission(auth, perm, func(c *gin.Context) iam.GroupRef {
			return iam.GroupByID(c.GetString("channel"))
		})
	}

	ch := r.Group("/c/:channel", f.channel) // every route below knows its channel
	ch.GET("/posts", f.list(true))          // anyone can read
	ch.POST("/posts", signedIn, f.create)   // anyone signed in can post
	ch.GET("/queue", may("channel:posts:approve"), f.list(false))
	ch.PATCH("/posts/:id", may("channel:posts:edit"), f.edit)
	ch.DELETE("/posts/:id", may("channel:posts:delete"), f.remove)
	ch.POST("/posts/:id/approve", may("channel:posts:approve"), f.approve)
	ch.PUT("/moderators/:user_id", signedIn, f.appoint) // AuthKit checks who may hand out badges
	ch.DELETE("/moderators/:user_id", signedIn, f.appoint)
}
```

Last come the posts. Each one belongs to a channel. They live in memory to keep the story short; a real app would keep them in a table. See how `create` asks AuthKit who is posting.

```go
type Post struct {
	ID        int    `json:"id"`
	ChannelID string `json:"channel_id"`
	AuthorID  string `json:"author_id"`
	Title     string `json:"title" binding:"required"`
	Body      string `json:"body"`
	Approved  bool   `json:"approved"` // new posts wait for a moderator
}

type forum struct {
	auth   *authkit.Auth
	mu     sync.Mutex
	posts  map[int]*Post
	nextID int
}

// channel finds the channel in the URL, or answers 404.
func (f *forum) channel(c *gin.Context) {
	g, err := f.auth.Group(c.Request.Context(), iam.GroupBySlug("channel", c.Param("channel")))
	if err != nil {
		authkitgin.Error(c, err)
		return
	}
	c.Set("channel", g.ID)
}

func (f *forum) list(approved bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []Post{}
		for _, p := range f.posts {
			if p.ChannelID == c.GetString("channel") && p.Approved == approved {
				out = append(out, *p)
			}
		}
		slices.SortFunc(out, func(a, b Post) int { return a.ID - b.ID })
		c.JSON(http.StatusOK, out)
	}
}

func (f *forum) create(c *gin.Context) {
	who, ok := authkitgin.Actor(c) // who is posting?
	if !ok || who.Kind() != iam.ActorUser {
		c.JSON(http.StatusForbidden, gin.H{"error": "only people can post"})
		return
	}
	var p Post
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	p.ID, p.ChannelID, p.AuthorID, p.Approved = f.nextID, c.GetString("channel"), who.ID(), false
	f.posts[p.ID] = &p
	c.JSON(http.StatusCreated, p)
}

func (f *forum) edit(c *gin.Context) {
	var in Post
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	f.withPost(c, func(p *Post) { p.Title, p.Body = in.Title, in.Body })
}

func (f *forum) approve(c *gin.Context) { f.withPost(c, func(p *Post) { p.Approved = true }) }
func (f *forum) remove(c *gin.Context)  { f.withPost(c, func(p *Post) { delete(f.posts, p.ID) }) }

// withPost finds the post in the URL and changes it, or answers 404.
// A post from another channel isn't here, so /c/rust can't reach a /c/golang post.
func (f *forum) withPost(c *gin.Context, change func(*Post)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, _ := strconv.Atoi(c.Param("id"))
	p, ok := f.posts[id]
	if !ok || p.ChannelID != c.GetString("channel") {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such post"})
		return
	}
	change(p)
	c.JSON(http.StatusOK, p)
}

// appoint pins the moderator badge on someone in this channel (PUT) or takes it back (DELETE).
// AuthKit decides whether the caller may: this channel's owner or an admin, yes; Bob, no.
func (f *forum) appoint(c *gin.Context) {
	actor, _ := authkitgin.Actor(c) // no actor? AuthKit refuses the empty one
	change := f.auth.AssignGroupRoles
	if c.Request.Method == http.MethodDelete {
		change = f.auth.UnassignGroupRoles
	}
	who := []iam.Subject{iam.UserSubject(c.Param("user_id"))}
	res, err := change(c.Request.Context(), actor, iam.GroupByID(c.GetString("channel")), who, "moderator")
	if err == nil {
		err = res[0].Err
	}
	if err != nil {
		authkitgin.Error(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
```

More: [routes](docs/api-endpoints.md) · [tokens and claims](docs/verification.md) · [rate limits](docs/security/rate-limits.md) · [keys.json](jwtkit/KEY_ROTATION.md)
