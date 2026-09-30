package authtest

import (
	"net/url"
	"testing"

	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/provider"
)

// IdP is an OpenID Provider on a local TLS server, for tests of signing in
// with an identity provider: discovery, JWKS, and the token and userinfo
// endpoints. A sign-in start redirects the browser to it; SignIn answers the
// way it would.
type IdP struct{ idp *testidp.IdP }

// NewIdP starts an IdP, closed at the test's cleanup.
func NewIdP(t testing.TB) *IdP { return &IdP{idp: testidp.New(t)} }

// Provider is an OpenID Connect provider named name for this IdP, trusted to
// verify email, for Deps.Providers. opts come after the defaults.
func (p *IdP) Provider(name string, opts ...provider.Option) provider.Provider {
	return p.idp.OIDC(name, opts...)
}

// SignIn is the query of the IdP's redirect back to AuthKit's callback once
// user signs in at authURL, the IdP URL a sign-in start redirected to: its
// state and a code. AuthKit redeems the code for an ID token naming user's
// Subject, Email (verified when EmailVerified), PreferredUsername and
// DisplayName.
func (p *IdP) SignIn(t testing.TB, authURL string, user provider.Identity) url.Values {
	t.Helper()
	return p.idp.Redirect(t, authURL, testidp.Identity{Subject: user.Subject, Email: user.Email, EmailVerified: user.EmailVerified,
		Username: user.PreferredUsername, Name: user.DisplayName})
}
