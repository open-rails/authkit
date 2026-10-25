// Package harness supplies real AuthKit runtimes for the critical browser suite.
package harness

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/helpers/notify"
)

const Persona = "project"

// Runtime contains the real service and a capture of its external deliveries.
type Runtime struct {
	*authkit.Client
	Outbox *authtest.Outbox
}

func New(ctx context.Context, origin, schema string, pool *pgxpool.Pool, profile string) (*Runtime, error) {
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
	limits := authkit.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
	}
	if profile == "limited" {
		limits["capabilities_read"] = authkit.RateLimit{Limit: 1, Window: time.Minute}
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
		DefaultTenantID:      tenant,
		Notifications:        &authkit.NotificationsConfig{Schema: schema, AppID: "critical-browser", Producers: []authkit.NotificationProducer{{Name: "application", TenantID: tenant, Origin: notify.OriginScope{System: "application", Scope: "critical-browser"}, Visibility: notify.VisibilityApp, AppID: "critical-browser"}}},
		Roles:                roles,
		HTTP:                 &authkit.HTTPConfig{DirectPeerIP: true, RefreshCookie: true, RateLimits: limits},
		Database:             authkit.DatabaseConfig{Schema: schema},
		Token:                authkit.TokenConfig{Issuer: origin, IssuedAudiences: []string{"critical-browser"}, SessionMaxPerUser: 10},
		Frontend:             authkit.FrontendConfig{BaseURL: origin},
		Registration:         authkit.RegistrationConfig{Verification: iam.RegistrationVerificationRequired, PasswordlessLogin: true},
		TwoFactor:            authkit.TwoFactorConfig{Mode: iam.TwoFactorOptional, TOTPSecretKey: totpKey},
		PersonalAccessTokens: authkit.PersonalAccessTokensConfig{Enabled: true},
	}
	if profile == "unproved" {
		cfg.Registration.Verification = iam.RegistrationVerificationOptional
	}
	client, err := authkit.New(ctx, cfg, authkit.Deps{
		Postgres:  pool,
		KeySource: keys.Static{Active: signer, Public: map[string]crypto.PublicKey{signer.KID(): signer.Public()}},
		Email:     outbox.Email(), SMS: outbox.SMS(),
	})
	if err != nil {
		return nil, err
	}
	return &Runtime{Client: client, Outbox: outbox}, nil
}
