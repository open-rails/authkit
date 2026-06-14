package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
)

// C-2: AuthKit must never silently link a fresh OIDC/OAuth2 identity to a
// pre-existing local account by matching its asserted email — that lets a
// hostile/lying IdP take over the victim's account. The callback must refuse and
// direct the user to the authenticated /oidc/link/start flow.

// Deterministic, no DB: the shared outcome is a 409 with the stable code that
// frontends route on.
func TestAccountExistsLinkRequiredOutcome(t *testing.T) {
	w := httptest.NewRecorder()
	accountExistsLinkRequired(w)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "account_exists_link_required")
}

func newAccountLinkPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// The core takeover assertion: when a local account already owns the asserted
// email, resolveOAuthUser refuses (errAccountExistsLinkRequired) and creates NO
// link to the attacker's provider identity.
func TestResolveOAuthUser_ExistingEmail_RefusesSilentLink(t *testing.T) {
	pool := newAccountLinkPG(t)
	ctx := context.Background()
	coreSvc := core.NewService(
		core.Options{Issuer: "https://example.com", NativeUserRegistrationMode: core.RegistrationModeOpen},
		core.Keyset{},
	).WithPostgres(pool)
	s := &Service{svc: coreSvc}

	const email = "c2-victim@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	victim, err := coreSvc.CreateUser(ctx, email, "c2victim")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, victim.ID) })

	cfg := authprovider.Provider{Name: "github", Kind: authprovider.KindOAuth2, Issuer: "https://github.com/login/oauth"}
	// Attacker controls a provider identity that asserts the victim's (verified!)
	// email — the strongest version of the attack.
	info := oauth2UserInfo{Subject: "attacker-subject", Email: email, EmailVerified: true}

	uid, created, err := s.resolveOAuthUser(httptest.NewRequest(http.MethodGet, "/", nil), cfg, oidckit.StateData{}, info)
	require.ErrorIs(t, err, errAccountExistsLinkRequired)
	require.Empty(t, uid)
	require.False(t, created)

	// Crucially: the attacker identity must NOT have been linked to the victim.
	linkedUID, _, _ := coreSvc.GetProviderLinkByIssuer(ctx, cfg.Issuer, "attacker-subject")
	require.Empty(t, linkedUID, "attacker provider identity must not be linked to the victim account")
}

// The explicit link flow (authenticated session, sd.LinkUserID set) still links
// even when the email collides — that is the supported, safe path.
func TestResolveOAuthUser_LinkFlow_StillLinksExistingEmail(t *testing.T) {
	pool := newAccountLinkPG(t)
	ctx := context.Background()
	coreSvc := core.NewService(
		core.Options{Issuer: "https://example.com", NativeUserRegistrationMode: core.RegistrationModeOpen},
		core.Keyset{},
	).WithPostgres(pool)
	s := &Service{svc: coreSvc}

	const email = "c2-linker@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	owner, err := coreSvc.CreateUser(ctx, email, "c2linker")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, owner.ID) })

	cfg := authprovider.Provider{Name: "github", Kind: authprovider.KindOAuth2, Issuer: "https://github.com/login/oauth"}
	info := oauth2UserInfo{Subject: "owner-subject", Email: email, EmailVerified: true}

	// Authenticated link flow: the owner is signed in (LinkUserID) and chooses to
	// link the provider. This is allowed and binds to the owner's own account.
	uid, created, err := s.resolveOAuthUser(
		httptest.NewRequest(http.MethodGet, "/", nil), cfg,
		oidckit.StateData{LinkUserID: owner.ID}, info,
	)
	require.NoError(t, err)
	require.Equal(t, owner.ID, uid)
	require.False(t, created)

	linkedUID, _, _ := coreSvc.GetProviderLinkByIssuer(ctx, cfg.Issuer, "owner-subject")
	require.Equal(t, owner.ID, linkedUID)
}

// A brand-new identity with a never-seen email creates a fresh account, and an
// unverified (or absent) email_verified claim must NOT mark the new account's
// email verified.
func TestResolveOAuthUser_NewEmail_UnverifiedClaimNotTrusted(t *testing.T) {
	pool := newAccountLinkPG(t)
	ctx := context.Background()
	coreSvc := core.NewService(
		core.Options{Issuer: "https://example.com", NativeUserRegistrationMode: core.RegistrationModeOpen},
		core.Keyset{},
	).WithPostgres(pool)
	s := &Service{svc: coreSvc}

	const email = "c2-fresh@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email) })

	cfg := authprovider.Provider{Name: "github", Kind: authprovider.KindOAuth2, Issuer: "https://github.com/login/oauth"}
	info := oauth2UserInfo{Subject: "fresh-subject", Email: email, EmailVerified: false}

	uid, created, err := s.resolveOAuthUser(httptest.NewRequest(http.MethodGet, "/", nil), cfg, oidckit.StateData{}, info)
	require.NoError(t, err)
	require.NotEmpty(t, uid)
	require.True(t, created)

	u, err := coreSvc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.False(t, u.EmailVerified, "absent/false email_verified claim must not mark the new account verified")
}
