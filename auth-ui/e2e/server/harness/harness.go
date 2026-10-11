// Package harness builds the AuthKit runtime the e2e server serves.
package harness

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

const (
	Schema   = "profiles"
	Audience = "auth-ui-e2e"
	// HostClient is the token-exchange client the page gets resource tokens
	// through.
	HostClient = "e2e-host"
	// ResourcePath is the test resource server, beneath the origin.
	ResourcePath = "/__test/resource"
	// ConsoleClient is a public client on another origin (ConsoleOrigin)
	// signing users in at this issuer.
	ConsoleClient = "e2e-console"
	// MerchantPersona's groups are what /__test/groups creates, giving the
	// user MerchantRole there.
	MerchantPersona = "merchant"
	MerchantRole    = "staff"
)

// The admin specs' roles. In a merchant group: staff reads billing only,
// viewer also sees members, roles and credentials, admin manages them but
// holds no billing:manage, so the owner outranks it. On root, rolesadmin
// reads members and defines custom roles.

// Resource is the test resource server's identifier (the tokens' aud).
func Resource(baseURL string) string { return baseURL + ResourcePath }

// ConsoleOrigin is the console's origin: the same server reached as
// 127.0.0.1, so the browser treats it as cross-origin to localhost.
func ConsoleOrigin(baseURL string) string {
	return strings.Replace(baseURL, "://localhost:", "://127.0.0.1:", 1)
}

// Runtime is a started-or-not AuthKit instance plus its captured deliveries
// and the identity provider it trusts.
type Runtime struct {
	*authkit.Client
	Outbox *authtest.Outbox
	IdP    *IdP
}

// Open connects to dsn; New creates AuthKit's tables.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, errors.New("harness: Postgres DSN is required")
	}
	return pgxpool.New(ctx, dsn)
}

// New builds the runtime for baseURL (the single same-origin SPA+API origin).
func New(baseURL string, pool *pgxpool.Pool) (*Runtime, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := keys.SignerFromKey("e2e-1", key)
	if err != nil {
		return nil, err
	}
	limits := authkit.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
	}
	outbox := &authtest.Outbox{}
	idp, err := NewIdP(baseURL)
	if err != nil {
		return nil, err
	}
	// Merchants: groups a resource token can be bound to (group_id), which
	// register their own OAuth clients.
	roles := authkit.NewRoles(authkit.CustomRoles)
	root := roles.Root
	root.Role("rolesadmin", root.Members.Read, root.Roles.Read, root.Roles.Manage)
	merchant := roles.Persona(MerchantPersona, authkit.APIKeys, authkit.CustomRoles, authkit.OAuthClients, authkit.RemoteApplications)
	billing := merchant.Permission("billing", "read")
	merchant.Permission("billing", "manage")
	merchant.Role(MerchantRole, billing)
	merchant.Role("viewer", billing, merchant.Members.Read, merchant.Roles.Read, merchant.Credentials.Read)
	merchant.Role("admin", billing, merchant.Members.Read, merchant.Members.Manage, merchant.Roles.Read,
		merchant.Roles.Manage, merchant.Credentials.Read, merchant.Credentials.Manage)
	cfg := authkit.Config{
		Roles: roles,
		HTTP: &authkit.HTTPConfig{
			DirectPeerIP:  true,
			RateLimits:    limits,
			RefreshCookie: true,
		},
		Database: authkit.DatabaseConfig{Schema: Schema},
		Token: authkit.TokenConfig{
			Issuer:          baseURL,
			IssuedAudiences: []string{Audience},
		},
		Frontend: authkit.FrontendConfig{BaseURL: baseURL, AuthorizePath: "/authorize.html"},
		Registration: authkit.RegistrationConfig{
			Verification:      iam.RegistrationVerificationRequired,
			PasswordlessLogin: true,
		},
		TwoFactor: authkit.TwoFactorConfig{
			Mode:          iam.TwoFactorOptional,
			TOTPSecretKey: []byte("auth-ui-e2e-totp-key-32-bytes!!!"),
		},
		Passkeys: authkit.PasskeyConfig{
			RPID:          "localhost",
			RPDisplayName: "auth-ui e2e",
			Origins:       []string{baseURL},
		},
		SolanaNetwork: "devnet",
		AuthorizationServer: authkit.AuthorizationServerConfig{
			Resources: []authkit.ResourceServerConfig{{ID: Resource(baseURL), Scopes: []string{"e2e:read"}}},
			Clients: []authkit.OAuthClientConfig{{
				ID: HostClient, Resources: []string{Resource(baseURL)},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantTokenExchange},
			}, {
				ID: ConsoleClient, Name: "E2E Console", Resources: []string{Resource(baseURL)},
				RedirectURIs:           []string{ConsoleOrigin(baseURL) + "/console.html"},
				PostLogoutRedirectURIs: []string{ConsoleOrigin(baseURL) + "/signed-out.html"},
				GrantTypes:             []authkit.OAuthGrantType{authkit.GrantAuthorizationCode, authkit.GrantRefreshToken},
			}},
		},
	}
	rt, err := authkit.New(context.Background(), cfg, authkit.Deps{
		Postgres: pool,
		KeySource: keys.Static{
			Active: signer,
			Public: map[string]crypto.PublicKey{signer.KID(): signer.Public()},
		},
		Providers: []provider.Provider{idp.Provider()},
		Email:     outbox.Email(),
		SMS:       outbox.SMS(),
	})
	if err != nil {
		return nil, err
	}
	return &Runtime{Client: rt, Outbox: outbox, IdP: idp}, nil
}
