package verify

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// AuthenticateRequest is r's helpers/auth Verified request, identity only: a
// Verifier checks no permissions.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return AuthenticateRequest(ctx, v, r)
}

// AuthenticateRequest is r's helpers/auth Verified request, for code written against
// helpers/auth providers. Behind a gate over a (Required, Optional,
// RequireSession, RequirePermission or Sensitive, in any adapter) it reuses
// the gate's verification, since verifying again would spend a DPoP proof
// twice; otherwise it verifies r through a. When a is a PermissionChecker
// (*authkit.Client), its Can checks the credential's permissions
// live, the session included; otherwise it is identity only.
func AuthenticateRequest(ctx context.Context, a Authenticator, r *http.Request) (auth.Verified, error) {
	cl, err := authenticate(ctx, a, r)
	if err != nil {
		return nil, err
	}
	return verifiedOf(a, cl)
}

// AuthenticateSession is AuthenticateRequest plus RequireSession's session
// check, for identity-only code that must stop the moment a sign-in is
// revoked (billing, say): a user's token is auth.ErrRevoked once its sign-in
// is revoked. Unlike RequireSession, a credential that carries no sign-in (an
// API key) passes: verification already refuses it once revoked, and Can
// checks its authority live. Admitting only some kinds is the caller's policy
// (Verified.Identity()).
func AuthenticateSession(ctx context.Context, a Authority, r *http.Request) (auth.Verified, error) {
	cl, err := authenticate(ctx, a, r)
	if err != nil {
		return nil, err
	}
	switch err := a.CheckSession(ctx, cl); {
	case err == nil, errmodel.CodeOf(err) == errmodel.CodeForbidden:
	case errors.Is(err, iam.ErrSessionRevoked):
		return nil, errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	default:
		return nil, errors.Join(auth.ErrUnavailable, err)
	}
	return verifiedOf(a, cl)
}

// authenticate is the claims a gate over a stored for r's credential, in ctx
// or r's context, else r verified through a.
func authenticate(ctx context.Context, a Authenticator, r *http.Request) (Claims, error) {
	if a == nil || r == nil {
		return Claims{}, auth.ErrUnauthenticated
	}
	for _, c := range []context.Context{ctx, r.Context()} {
		if cl, ok := verifiedBy(c, r, a); ok {
			return cl, nil
		}
	}
	cl, err := a.VerifyRequest(r.WithContext(ctx))
	if err != nil {
		return Claims{}, classify(r, err)
	}
	return cl, nil
}

// verifiedOf is verified claims' helpers/auth Verified request (see
// AuthenticateRequest for Can).
func verifiedOf(a Authenticator, cl Claims) (auth.Verified, error) {
	i, ok := cl.Identity()
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	cl.Permissions = append([]string(nil), cl.Permissions...)
	if authority, ok := a.(Authority); ok {
		return sessionVerified{checkingVerified{identity{i}, cl, authority}, authority}, nil
	}
	if checker, ok := a.(PermissionChecker); ok {
		return checkingVerified{identity{i}, cl, checker}, nil
	}
	return identity{i}, nil
}

type identity struct{ id auth.Identity }

func (p identity) Identity() auth.Identity { return p.id }

type checkingVerified struct {
	identity
	claims  Claims
	checker PermissionChecker
}

var _ auth.PermissionChecker = checkingVerified{}

// Can checks the credential's authority in the group scope.ID names, live
// and without verifying the request again. The scope's authority must be the
// credential's own (the issuer of the groups it acts in). A revoked session
// is auth.ErrRevoked.
func (p checkingVerified) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	if scope.ID == "" || permission == "" || scope.Authority == "" || scope.Authority != authorityOf(p.claims) {
		return false, nil
	}
	identity, ok := boundIdentity(p.claims)
	if !ok {
		return false, nil
	}
	allowed, err := p.checker.Can(ctx, identity, iam.GroupByID(scope.ID), ident.Perm(permission))
	switch {
	case errors.Is(err, iam.ErrSessionRevoked):
		return false, errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	case err != nil:
		return false, errors.Join(auth.ErrUnavailable, err)
	}
	return allowed, nil
}

// authorityOf is the issuer whose groups cl acts in.
func authorityOf(cl Claims) string {
	if cl.Group != nil {
		return cl.Group.AuthorityIssuer
	}
	return cl.Issuer
}

// classify maps r's verification error onto the helpers/auth taxonomy. A
// DPoP refusal is a *auth.Challenge carrying the headers DPoPChallenge
// writes (WWW-Authenticate, DPoP-Nonce).
func classify(r *http.Request, err error) error {
	out := classifyErr(err)
	if h := dpopChallenge(r, err); h != nil {
		return &auth.Challenge{Err: out, Header: h}
	}
	return out
}

func classifyErr(err error) error {
	var nonce dpopNonce
	switch {
	case errors.Is(err, ErrSenderProofRequired), errors.As(err, &nonce):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrSenderProofRequired, err)
	case errors.Is(err, iam.ErrAPIKeyExpired), errors.Is(err, iam.ErrTokenExpired):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, err)
	case errors.Is(err, iam.ErrAPIKeyRevoked):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	}
	if e, ok := iam.AsError(err); ok {
		switch {
		case e.Status() == http.StatusForbidden:
			return errors.Join(auth.ErrForbidden, err)
		case e.Status() >= http.StatusInternalServerError:
			return errors.Join(auth.ErrUnavailable, err)
		}
	}
	return errors.Join(auth.ErrUnauthenticated, err)
}

// sessionVerified is a checkingVerified whose authority also checks the
// credential's sign-in (*authkit.Client is one).
type sessionVerified struct {
	checkingVerified
	sessions SessionChecker
}

var _ auth.RecentSignInChecker = sessionVerified{}

// CheckRecentSignIn is Sensitive's check, live and without verifying the
// request again: the user's own token, signed in within the last 15 minutes,
// with the second factor when the account has one. A stale sign-in is a
// *auth.Challenge: auth.ErrStepUpRequired joined with step_up_required, the
// window as MaxAge, and the account's step-up methods as Metadata. A
// credential with no sign-in of its own (an API key) is auth.ErrForbidden,
// and a revoked session auth.ErrRevoked.
func (p sessionVerified) CheckRecentSignIn(ctx context.Context) error {
	err := p.sessions.CheckRecentSignIn(ctx, p.claims)
	switch code := errmodel.CodeOf(err); {
	case err == nil:
		return nil
	case code == errmodel.CodeStepUpRequired:
		return stepUpChallenge(err)
	case errors.Is(err, iam.ErrSessionRevoked):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	case code == errmodel.CodeForbidden:
		return errors.Join(auth.ErrForbidden, err)
	default:
		return errors.Join(auth.ErrUnavailable, err)
	}
}

// stepUpChallenge is err, when it is step_up_required, as a helpers/auth
// step-up challenge: auth.ErrStepUpRequired with the error's max age and its
// metadata (the account's step-up methods). Nil for any other error.
func stepUpChallenge(err error) *auth.Challenge {
	maxAge, metadata, ok := errmodel.StepUp(err)
	if !ok {
		return nil
	}
	return &auth.Challenge{Err: errors.Join(auth.ErrStepUpRequired, err), MaxAge: maxAge, Metadata: metadata}
}
