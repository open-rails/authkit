package authhttp

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// newRegistrationModeService builds an http.Service whose core Options carry the
// native-user registration mode under test. No DB; the registration-disabled
// gate fires before any storage call (a nil pool returns empty, not an error).
func newRegistrationModeService(t *testing.T, nativeMode embedded.RegistrationMode) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := embedded.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}, Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone, NativeUserMode: nativeMode}}
	coreSvc := newCore(t, opts, ks)
	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	_ = ver.AddIssuer(opts.Token.Issuer, opts.Token.ExpectedAudiences, verify.IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

// externalIdentity is the engine's view of a provider identity, as the
// callback builds it before CompleteExternalLogin.
func externalIdentity(p authprovider.Provider, id authprovider.Identity) embedded.ExternalIdentity {
	return embedded.ExternalIdentity{
		Provider: p.Name(), Issuer: p.Issuer(), Subject: id.Subject, Email: id.Email, EmailVerified: id.EmailVerified,
		PreferredUsername: id.PreferredUsername, DisplayName: id.DisplayName,
	}
}

// Auto-create (a public-registration path) is blocked when native-user
// registration is disabled. No DB: the disabled gate fires after the (empty)
// provider-link + email lookups.
func TestResolveOAuthUser_RegistrationDisabled_BlocksAutoCreate(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
	identity := authprovider.Identity{Subject: "brand-new-subject", Email: "newuser@example.com", EmailVerified: true}
	_, created, err := s.svc.ResolveExternalIdentity(context.Background(), embedded.ExternalLoginInput{Identity: externalIdentity(authprovider.GitHub("github-client", "github-secret"), identity)})
	require.ErrorIs(t, err, authkit.ErrRegistrationDisabled)
	require.False(t, created)
}

// The explicit link flow (StateData.LinkUserID set) is NOT a registration path,
// so it is unaffected by the registration-disabled gate.
func TestResolveOAuthUser_LinkFlow_IgnoresRegistrationDisabled(t *testing.T) {
	s := newRegistrationModeService(t, embedded.RegistrationModeClosed)
	identity := authprovider.Identity{Subject: "linked-subject", Email: "linked@example.com"}
	uid, created, err := s.svc.ResolveExternalIdentity(context.Background(), embedded.ExternalLoginInput{Identity: externalIdentity(authprovider.GitHub("github-client", "github-secret"), identity), LinkUserID: "user-123"})
	require.NoError(t, err)
	require.Equal(t, "user-123", uid)
	require.False(t, created)
}

// TestOAuthCallback_MissingStateOrCode exercises the browser callback
// entrypoint's request-validation gate through the real router (no DB): a
// browser navigation is walked back to the frontend with the error in the
// fragment, while a JSON caller keeps the legacy envelope.
func TestOAuthCallback_MissingStateOrCode(t *testing.T) {
	s := newTestService(t)
	// Register a github OAuth2 provider so the callback resolves past the
	// unknown-provider check and reaches the state/code validation.
	var err error
	s.providers, err = providerRegistry([]authprovider.Provider{
		authprovider.GitHub("github-client", "github-secret"),
	})
	require.NoError(t, err)
	h := s.oidcHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/github/callback", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusFound, w.Code)
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login/callback", target.Path)
	fragment, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.Equal(t, "invalid_request", fragment.Get("error"))
	require.Equal(t, "login", fragment.Get("flow"))

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/oidc/github/callback", nil)
	r.Header.Set("Accept", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)
}
