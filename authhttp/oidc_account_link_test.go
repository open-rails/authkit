package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
)

// C-2: AuthKit must never silently link a fresh OIDC/OAuth2 identity to a
// pre-existing local account by matching its asserted email — that lets a
// hostile/lying IdP take over the victim's account. The callback must refuse and
// direct the user to the authenticated /oidc/link/start flow.

// Deterministic, no DB: JSON callers keep the 409 with the stable code that
// frontends route on; browser navigations land on the frontend with the same
// code in the fragment.
func TestAccountExistsLinkRequiredOutcome(t *testing.T) {
	s := newTestService(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	r.Header.Set("Accept", "application/json")
	s.accountExistsLinkRequired(w, r, nil, "google")
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "account_exists_link_required")

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/google/callback", nil)
	s.accountExistsLinkRequired(w, r, nil, "google")
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=account_exists_link_required")
}

func TestOIDCLegacyBrowserLinkRejects2FAEnrollmentToken(t *testing.T) {
	s := newTestService(t)
	token, _, err := s.svc.Mint2FAEnrollmentToken(context.Background(), "user-1")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/google/login?link=1", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	s.handleOIDCLoginGET(w, r)

	// Still rejected — as a browser navigation the refusal now lands on the
	// frontend error fragment instead of a raw JSON body.
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=auth_required_for_link")
}

// The core takeover assertion: when a local account already owns the asserted
// email, resolveOAuthUser refuses (authkit.ErrAccountExistsLinkRequired) and creates NO
// link to the attacker's provider identity.
func TestResolveOAuthUser_ExistingEmail_RefusesSilentLink(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	ctx := context.Background()
	coreSvc := newCore(t,
		embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com"}, Registration: embedded.RegistrationConfig{NativeUserMode: embedded.RegistrationModeOpen}},
		embedded.Keyset{},
		withPostgres(pool),
	)
	s := &Service{svc: coreSvc}

	const email = "c2-victim@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	victim, err := coreSvc.CreateUser(ctx, email, "c2victim")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, victim.ID) })

	cfg := authprovider.GitHub("github-client", "github-secret")
	// Attacker controls a provider identity that asserts the victim's (verified!)
	// email — the strongest version of the attack.
	info := authprovider.Identity{Subject: "attacker-subject", Email: email, EmailVerified: true}

	uid, created, err := s.svc.ResolveExternalIdentity(context.Background(), embedded.ExternalLoginInput{Identity: externalIdentity(cfg, info)})
	require.ErrorIs(t, err, authkit.ErrAccountExistsLinkRequired)
	require.Empty(t, uid)
	require.False(t, created)

	// Crucially: the attacker identity must NOT have been linked to the victim.
	linkedUID, _, _ := coreSvc.GetProviderLinkByIssuer(ctx, cfg.Issuer(), "attacker-subject")
	require.Empty(t, linkedUID, "attacker provider identity must not be linked to the victim account")
}

// The explicit link flow (authenticated session, sd.LinkUserID set) still links
// even when the email collides — that is the supported, safe path.
func TestResolveOAuthUser_LinkFlow_StillLinksExistingEmail(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	ctx := context.Background()
	coreSvc := newCore(t,
		embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com"}, Registration: embedded.RegistrationConfig{NativeUserMode: embedded.RegistrationModeOpen}},
		embedded.Keyset{},
		withPostgres(pool),
	)
	s := &Service{svc: coreSvc}

	const email = "c2-linker@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	owner, err := coreSvc.CreateUser(ctx, email, "c2linker")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, owner.ID) })

	cfg := authprovider.GitHub("github-client", "github-secret")
	info := authprovider.Identity{Subject: "owner-subject", Email: email, EmailVerified: true}

	// Authenticated link flow: the owner is signed in (LinkUserID) and chooses to
	// link the provider. This is allowed and binds to the owner's own account.
	uid, created, err := s.svc.ResolveExternalIdentity(context.Background(), embedded.ExternalLoginInput{Identity: externalIdentity(cfg, info), LinkUserID: owner.ID})
	require.NoError(t, err)
	require.Equal(t, owner.ID, uid)
	require.False(t, created)

	linkedUID, _, _ := coreSvc.GetProviderLinkByIssuer(ctx, cfg.Issuer(), "owner-subject")
	require.Equal(t, owner.ID, linkedUID)
}

// A brand-new identity with a never-seen email creates a fresh account, and an
// unverified (or absent) email_verified claim must NOT mark the new account's
// email verified.
func TestResolveOAuthUser_NewEmail_UnverifiedClaimNotTrusted(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	ctx := context.Background()
	coreSvc := newCore(t,
		embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com"}, Registration: embedded.RegistrationConfig{NativeUserMode: embedded.RegistrationModeOpen}},
		embedded.Keyset{},
		withPostgres(pool),
	)
	s := &Service{svc: coreSvc}

	const email = "c2-fresh@example.com"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email) })

	cfg := authprovider.GitHub("github-client", "github-secret")
	info := authprovider.Identity{Subject: "fresh-subject", Email: email, EmailVerified: false}

	uid, created, err := s.svc.ResolveExternalIdentity(context.Background(), embedded.ExternalLoginInput{Identity: externalIdentity(cfg, info)})
	require.NoError(t, err)
	require.NotEmpty(t, uid)
	require.True(t, created)

	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, uid) })
	u, err := coreSvc.AdminGetUser(ctx, uid)
	require.NoError(t, err)
	require.Nil(t, u.Email)
	byEmail, err := coreSvc.GetUserByEmail(ctx, email)
	require.ErrorIs(t, err, pgx.ErrNoRows)
	require.Nil(t, byEmail)
	owner, providerEmail, err := coreSvc.GetProviderLinkByIssuer(ctx, cfg.Issuer(), info.Subject)
	require.NoError(t, err)
	require.Equal(t, uid, owner)
	require.NotNil(t, providerEmail)
	require.Equal(t, email, *providerEmail)
}
