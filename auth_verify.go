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

// VerifyRequest authenticates r: one of this deployment's API keys, a token
// it issued, or a token one of its remote applications issued. Its own
// tokens are verified statelessly, so a token outlives its revoked session
// until it expires; CheckSession and the live gates (verify.RequireSession,
// RequirePermission, Sensitive) check it.
func (a *Client) VerifyRequest(r *http.Request) (verify.Claims, error) {
	return a.engine.VerifyRequest(r)
}

// Verify is VerifyRequest for a token detached from any request (a
// WebSocket message, a queue job); a sender-bound delegated token fails with
// verify.ErrSenderProofRequired.
func (a *Client) Verify(ctx context.Context, token string) (verify.Claims, error) {
	return a.engine.Verify(ctx, token)
}

// VerifyServiceJWT verifies a service JWT this deployment (MintServiceJWT)
// or one of its remote applications issued. It grants nothing: the host
// intersects the requested permissions with its own grants.
func (a *Client) VerifyServiceJWT(ctx context.Context, token string, opts ...verify.ServiceJWTVerifyOption) (iam.ServiceJWTClaims, error) {
	return a.engine.VerifyServiceJWT(ctx, token, opts...)
}

// AuthenticateRequest is r's helpers/auth Verified request, whose Can checks
// permissions live (verify.AuthenticateRequest: behind a gate over the
// Client it reuses the gate's verification).
func (a *Client) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return verify.AuthenticateRequest(ctx, a, r)
}

// CheckIssuerKeys is a no-I/O health probe of the remote applications' JWKS
// keys: it fails naming every application whose last key fetch failed, with
// the age of its keys and whether they are past max-stale (its tokens then
// fail closed).
func (a *Client) CheckIssuerKeys(ctx context.Context) error { return a.engine.CheckIssuerKeys(ctx) }

// IssuerKeyStatuses reports the remote applications' JWKS key state and age.
func (a *Client) IssuerKeyStatuses() []verify.IssuerKeyStatus { return a.engine.IssuerKeyStatuses() }

// NewVerifier builds a Verifier for a host resource server in this process:
// this deployment's API keys and tokens and its remote applications' tokens,
// for audiences. DPoP proofs are spent once in AuthKit's replay store and
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
// keys and remote applications from AuthKit's database, and its live gates
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

// VerifyServiceJWT is Client.VerifyServiceJWT for this Verifier's audiences.
func (v *Verifier) VerifyServiceJWT(ctx context.Context, token string, opts ...verify.ServiceJWTVerifyOption) (iam.ServiceJWTClaims, error) {
	return v.auth.VerifyServiceJWT(ctx, token, opts...)
}

// AuthenticateRequest is Client.AuthenticateRequest for this Verifier.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return verify.AuthenticateRequest(ctx, v, r)
}

// Can is Client.Can.
func (v *Verifier) Can(ctx context.Context, actor iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error) {
	return v.client.Can(ctx, actor, ref, perm)
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

// CheckIssuerKeys is Client.CheckIssuerKeys for this Verifier.
func (v *Verifier) CheckIssuerKeys(ctx context.Context) error { return v.auth.CheckIssuerKeys(ctx) }

// IssuerKeyStatuses is Client.IssuerKeyStatuses for this Verifier.
func (v *Verifier) IssuerKeyStatuses() []verify.IssuerKeyStatus { return v.auth.IssuerKeyStatuses() }
