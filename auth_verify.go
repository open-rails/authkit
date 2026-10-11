package authkit

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/engine"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// Request authentication. The Client is a verify.Authority for
// Config.Token.ExpectedAudiences: pass it to verify.Required,
// verify.RequirePermission and the adapters. NewVerifier builds one for a
// host resource server's own audiences.

// VerifyRequest authenticates r: one of this deployment's API keys or a
// token it issued. Its tokens are verified statelessly, so a token outlives its revoked session
// until it expires; CheckSession and the live gates (verify.RequireSession,
// RequirePermission, Sensitive) check it.
func (a *Client) VerifyRequest(r *http.Request) (verify.Claims, error) {
	return a.engine.VerifyRequest(r)
}

// Verify is VerifyRequest for a token detached from any request (a
// WebSocket message, a queue job).
func (a *Client) Verify(ctx context.Context, token string) (verify.Claims, error) {
	return a.engine.Verify(ctx, token)
}

// AuthenticateRequest is r's helpers/auth Verified request, whose Can checks
// permissions live (verify.AuthenticateRequest: behind a gate over the
// Client it reuses the gate's verification).
func (a *Client) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return verify.AuthenticateRequest(ctx, a, r)
}

// NewVerifier builds a Verifier for a host resource server in this process:
// this deployment's API keys and tokens, for audiences. DPoP proofs are spent once in AuthKit's replay store and
// checked against verify.WithPublicURL (default: the issuer's origin).
func (a *Client) NewVerifier(audiences []string, opts ...verify.VerifierOption) (*Verifier, error) {
	v, err := a.engine.NewAuthenticator(audiences, opts...)
	if err != nil {
		return nil, err
	}
	return &Verifier{client: a, auth: v}, nil
}

// Verifier is a Client's verifier for a host resource server's audiences
// (Client.NewVerifier), a verify.Authority like the Client: it reads API
// keys from AuthKit's database, and its live gates
// check sessions and permissions through the Client. It applies no 2FA
// policy.
type Verifier struct {
	client *Client
	auth   *engine.Authenticator
}

var _ verify.Authority = (*Verifier)(nil)

// VerifyRequest authenticates r (Client.VerifyRequest, for this Verifier's
// audiences).
func (v *Verifier) VerifyRequest(r *http.Request) (verify.Claims, error) {
	return v.auth.VerifyRequest(r)
}

// Verify is VerifyRequest for a token detached from any request.
func (v *Verifier) Verify(ctx context.Context, token string) (verify.Claims, error) {
	return v.auth.Verify(ctx, token)
}

// AuthenticateRequest is Client.AuthenticateRequest for this Verifier.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return verify.AuthenticateRequest(ctx, v, r)
}

// Can is Client.Can.
func (v *Verifier) Can(ctx context.Context, who auth.Identity, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	return v.client.Can(ctx, who, ref, perm)
}

// KnownPermission is Client.KnownPermission.
func (v *Verifier) KnownPermission(perm iam.Perm) bool { return v.client.KnownPermission(perm) }

// CheckSession is Client.CheckSession.
func (v *Verifier) CheckSession(ctx context.Context, cl verify.Claims) error {
	return v.client.CheckSession(ctx, cl)
}

// CheckRecentSignIn is Client.CheckRecentSignIn.
func (v *Verifier) CheckRecentSignIn(ctx context.Context, cl verify.Claims) error {
	return v.client.CheckRecentSignIn(ctx, cl)
}

// VerifyIDToken verifies an ID token this deployment's authorization server
// issued (Config.AuthorizationServer), such as one a client hands back to
// prove a fresh sign-in: its signature, issuer, single audience, lifetime,
// a client still registered and enabled, and a sign-in that still stands.
// The caller compares the audience, nonce and auth_time it expects. Any
// refusal is iam.ErrInvalidIDToken.
func (a *Client) VerifyIDToken(ctx context.Context, raw string) (iam.IDToken, error) {
	return a.engine.VerifyIDToken(ctx, raw)
}
