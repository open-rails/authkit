// Package harness supplies real AuthKit runtimes for the critical browser suite.
package harness

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"slices"
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
		DefaultTenantID: tenant,
		Roles:           roles,
		HTTP:            &authkit.HTTPConfig{DirectPeerIP: true, Groups: append(iam.DefaultRouteGroups(), iam.RoutePasswordless, iam.RoutePersonalAccessTokens)},
		Database:        authkit.DatabaseConfig{Schema: schema},
		Issuer:          origin,
		TwoFactor:       iam.TwoFactorOptional,
	}
	config.Tune(&cfg, func(tn *config.Tuning) {
		tn.RateLimits = limits
		tn.SessionMaxPerUser = 10
	})
	if profile == "main" {
		cfg.Tenancy = authkit.TenancyMulti // and an isolated directory
		cfg.AuthorizationServer = authkit.AuthorizationServerConfig{Clients: []authkit.OAuthClientConfig{{
			ID: "critical-issuer", Name: "Critical issuer proof", RedirectURIs: []string{origin + "/issuer-return"},
		}}}
	}
	if profile == "unproved" {
		cfg.HTTP.Groups = slices.DeleteFunc(cfg.HTTP.Groups, func(g iam.RouteGroup) bool { return g == iam.RouteInvitations })
	}
	client, err := authkit.New(ctx, cfg, authkit.Deps{
		Postgres:      pool,
		KeySource:     keys.Static{Active: signer, Public: map[string]crypto.PublicKey{signer.KID(): signer.Public()}, TOTP: totpKey},
		RequestTenant: requestTenant,
		Email:         outbox.Email(), SMS: outbox.SMS(),
	})
	if err != nil {
		return nil, err
	}
	return &Runtime{Client: client, Outbox: outbox}, nil
}
