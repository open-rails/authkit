// Command reddit is the example from the README: a tiny Reddit-like forum where
// channels live in the app and AuthKit keeps who may do what in each of them.
//
// It needs DATABASE_URL, ADMIN_EMAIL, and signing keys at /vault/auth (see docs/keys.md).
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
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

func newAuth(ctx context.Context, db *pgxpool.Pool) (*authkit.Client, error) {
	cfg := authkit.Config{
		Database: authkit.DatabaseConfig{Schema: "profiles"}, // the Postgres schema AuthKit's tables go in
		// Configure JWTs; authkit issues these to users; users then send them back with requests to prove who they are!
		Token: authkit.TokenConfig{
			Issuer:          "https://myapp.com", // who issued this; that's you!
			IssuedAudiences: []string{"myapp"},   // who this JWT is intended for (doesn't have to be yourself, but usually is)
		},
		Keys: authkit.KeysConfig{
			Path: "/vault/auth", // where your signing keys are stored; a keys.json file
		},
		HTTP: &authkit.HTTPConfig{
			DirectPeerIP: true, // no proxy in front; otherwise set TrustedProxies
			// Rate limits are counted in Postgres, shared by every copy of your server; Deps.Redis is optional.
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
		Postgres: db,    // required: users, sessions and short-lived auth state
		Email:    email, // sends verification codes, login codes and password resets
		SMS:      sms,   // same, for phone numbers
		// Both also report when they can't deliver, pausing that channel's sign-in until they can.
	})
}

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

type Post struct {
	ID        int    `json:"id"`
	ChannelID string `json:"channel_id"`
	AuthorID  string `json:"author_id"`
	Title     string `json:"title" binding:"required"`
	Body      string `json:"body"`
	Approved  bool   `json:"approved"` // new posts wait for a moderator
}

type forum struct {
	auth   *authkit.Client
	db     *pgxpool.Pool
	mu     sync.Mutex
	posts  map[int]*Post
	nextID int
}

// channel finds the channel in the URL, or answers 404.
func (f *forum) channel(c *gin.Context) {
	var groupID string
	err := f.db.QueryRow(c.Request.Context(), `SELECT group_id FROM channels WHERE name = $1`, c.Param("channel")).Scan(&groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no such channel"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(iam.ErrorResponse(err))
		return
	}
	c.Set("channel", groupID)
	authkitgin.SetGroup(c, iam.GroupByID(groupID)) // the group RequirePermission checks
}

// ChannelRow is what our channels table says about a channel.
type ChannelRow struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// listChannels is GET /c: every channel, straight from our own table.
func (f *forum) listChannels(c *gin.Context) {
	rows, err := f.db.Query(c.Request.Context(), `SELECT name, description FROM channels ORDER BY name`)
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ChannelRow])
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.JSON(http.StatusOK, out)
}

// getChannel is GET /c/:channel: one channel's page.
func (f *forum) getChannel(c *gin.Context) {
	var out ChannelRow
	err := f.db.QueryRow(c.Request.Context(), `SELECT name, description FROM channels WHERE group_id = $1`,
		c.GetString("channel")).Scan(&out.Name, &out.Description)
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.JSON(http.StatusOK, out)
}

// createChannel is POST /c. Which names are taken is our rule, not AuthKit's.
func (f *forum) createChannel(c *gin.Context) {
	who, ok := verify.IdentityFromContext(c.Request.Context())
	if !ok || who.SubjectKind != auth.SubjectUser {
		c.JSON(http.StatusForbidden, gin.H{"error": "only people can start channels"})
		return
	}
	var in struct {
		Name string `json:"name" binding:"required,alphanum,lowercase"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.Name == "announcements" {
		c.JSON(http.StatusForbidden, gin.H{"error": "that name is reserved"})
		return
	}
	err := createChannel(c.Request.Context(), f.db, f.auth, in.Name, who.Subject)
	if errors.Is(err, errChannelTaken) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.Status(http.StatusCreated)
}

// editChannel changes the channel's description.
func (f *forum) editChannel(c *gin.Context) {
	var in struct {
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err := f.db.Exec(c.Request.Context(), `UPDATE channels SET description = $2 WHERE group_id = $1`, c.GetString("channel"), in.Description)
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.Status(http.StatusNoContent)
}

// deleteChannel deletes our row and AuthKit's permission group together.
func (f *forum) deleteChannel(c *gin.Context) {
	ctx, id := c.Request.Context(), c.GetString("channel")
	err := pgx.BeginFunc(ctx, f.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM channels WHERE group_id = $1`, id); err != nil {
			return err
		}
		return f.auth.DeleteGroup(ctx, iam.GroupByID(id), authkit.InTx(tx))
	})
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.Status(http.StatusNoContent)
}

func (f *forum) listPosts(approved bool) gin.HandlerFunc {
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

func (f *forum) createPost(c *gin.Context) {
	who, ok := verify.IdentityFromContext(c.Request.Context()) // who is posting?
	if !ok || who.SubjectKind != auth.SubjectUser {
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
	p.ID, p.ChannelID, p.AuthorID, p.Approved = f.nextID, c.GetString("channel"), who.Subject, false
	f.posts[p.ID] = &p
	c.JSON(http.StatusCreated, p)
}

func (f *forum) editPost(c *gin.Context) {
	var in Post
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	f.withPost(c, func(p *Post) { p.Title, p.Body = in.Title, in.Body })
}

func (f *forum) approvePost(c *gin.Context) { f.withPost(c, func(p *Post) { p.Approved = true }) }
func (f *forum) deletePost(c *gin.Context)  { f.withPost(c, func(p *Post) { delete(f.posts, p.ID) }) }

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
	requester, _ := verify.IdentityFromContext(c.Request.Context()) // none? AuthKit refuses the empty one
	ctx, channel, who := c.Request.Context(), iam.GroupByID(c.GetString("channel")), iam.UserSubject(c.Param("user_id"))
	var err error
	if c.Request.Method == http.MethodDelete {
		err = f.auth.RemoveGroupMember(ctx, requester, channel, who, authkit.IfRole(Moderator)) // a moderator only
	} else {
		_, err = f.auth.SetGroupRole(ctx, requester, channel, who, Moderator)
	}
	if err != nil {
		c.JSON(iam.ErrorResponse(err))
		return
	}
	c.Status(http.StatusNoContent)
}
