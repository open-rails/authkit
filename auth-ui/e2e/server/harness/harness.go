// Package harness supplies real AuthKit runtimes for the critical browser suite.
package harness

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/keys"
)

const Persona = "project"

// Runtime contains the real service and a capture of its external deliveries.
type Runtime struct {
	*authkit.Client
	Outbox *authtest.Outbox
	setup  *setupLinks
}

// SetupLink is the last setup link Start logged, "" for none.
func (r *Runtime) SetupLink() string { return r.setup.last() }

// setupLinks passes every record on to next and keeps the setup links.
type setupLinks struct {
	next slog.Handler
	mu   *sync.Mutex
	urls *[]string
}

func (h setupLinks) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }
func (h setupLinks) Handle(ctx context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "url" && strings.Contains(r.Message, "no administrator yet") {
			h.mu.Lock()
			*h.urls = append(*h.urls, a.Value.String())
			h.mu.Unlock()
		}
		return true
	})
	return h.next.Handle(ctx, r)
}
func (h setupLinks) WithAttrs(a []slog.Attr) slog.Handler {
	h.next = h.next.WithAttrs(a)
	return h
}
func (h setupLinks) WithGroup(g string) slog.Handler {
	h.next = h.next.WithGroup(g)
	return h
}
func (h *setupLinks) last() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(*h.urls) == 0 {
		return ""
	}
	return (*h.urls)[len(*h.urls)-1]
}

func New(ctx context.Context, origin, schema string, pool *pgxpool.Pool, profile string, requestTenant func(*http.Request) (iam.TenantID, error)) (*Runtime, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := keys.SignerFromKey("critical-browser", private)
	if err != nil {
		return nil, err
	}
	roles := authkit.NewRoles(authkit.CustomRoles)
	root := roles.Root
	root.Role("reader", root.Users.Read)
	root.Role("auditor", root.Users.Read, root.Members.Read)
	root.Role("operator", root.Users.Read, root.Users.Manage, root.Users.Ban, root.Users.Delete, root.Members.Read, root.Members.Manage, root.Roles.Read, root.Roles.Manage)
	project := roles.Persona(Persona, authkit.APIKeys, authkit.CustomRoles)
	read := project.Permission("records", "read")
	write := project.Permission("records", "write")
	project.Role("viewer", read)
	project.Role("manager", read, write, project.Members.Read, project.Members.Manage, project.Roles.Read, project.Roles.Manage, project.Credentials.Read, project.Credentials.Manage)
	limits := httpapi.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = config.RateLimit{Limit: 10000, Window: time.Minute}
	}
	if profile == "limited" {
		limits["capabilities_read"] = config.RateLimit{Limit: 1, Window: time.Minute}
	}
	tenant, err := iam.ParseTenantID("00000000-0000-4000-8000-000000001290")
	if err != nil {
		return nil, err
	}
	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		return nil, err
	}
	outbox := &authtest.Outbox{}
	cfg := authkit.Config{
		Roles:     roles,
		HTTP:      &authkit.HTTPConfig{DirectPeerIP: true, Groups: append(iam.DefaultRouteGroups(), iam.RoutePasswordless, iam.RoutePersonalAccessTokens)},
		Database:  authkit.DatabaseConfig{Schema: schema},
		Issuer:    origin,
		TwoFactor: iam.TwoFactorOptional,
	}
	config.Tune(&cfg, func(tn *config.Tuning) {
		tn.RateLimits = limits
		tn.SessionMaxPerUser = 10
	})
	if profile == "main" {
		cfg.Tenancy = authkit.TenancyMulti // and an isolated directory
		cfg.DefaultTenantID = tenant
		cfg.AuthorizationServer = authkit.AuthorizationServerConfig{Clients: []authkit.OAuthClientConfig{{
			ID: "critical-issuer", Name: "Critical issuer proof", RedirectURIs: []string{origin + "/issuer-return"},
		}}}
	}
	if profile == "unproved" {
		cfg.HTTP.Groups = slices.DeleteFunc(cfg.HTTP.Groups, func(g iam.RouteGroup) bool { return g == iam.RouteInvitations })
	}
	setup := &setupLinks{next: slog.NewTextHandler(os.Stderr, nil), mu: &sync.Mutex{}, urls: &[]string{}}
	deps := authkit.Deps{
		Logger:        slog.New(setup),
		Postgres:      pool,
		KeySource:     keys.Static{Active: signer, Public: map[string]crypto.PublicKey{signer.KID(): signer.Public()}, TOTP: totpKey},
		RequestTenant: requestTenant,
		Email:         outbox.Email(), SMS: outbox.SMS(),
	}
	// A deployment that sends no email, nor any text.
	if profile == "noemail" {
		deps.Email, deps.SMS = nil, nil
	}
	client, err := authkit.New(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	return &Runtime{Client: client, Outbox: outbox, setup: setup}, nil
}
