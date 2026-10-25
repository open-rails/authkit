package verify

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
)

// AuthenticateRequest is r's authkit/auth Verified request, identity only: a
// Verifier checks no permissions.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Verified, error) {
	return AuthenticateRequest(ctx, v, r)
}

// AuthenticateRequest is r's authkit/auth Verified request, for code written against
// authkit/auth providers. Behind a gate over a (Required, Optional,
// RequireSession, RequirePermission or Sensitive, in any adapter) it reuses
// the gate's verification, since verifying again would spend a DPoP proof
// twice; otherwise it verifies r through a. When a is a PermissionChecker
// (*authkit.Client), its Can checks the credential's permissions
// live, the session included; otherwise it is identity only. Either way its
// Entitlements() []string is the token's entitlements claim.
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
	case errors.Is(err, iam.ErrTokenExpired):
		return nil, errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, err)
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
			return cl, credentialExpiry(cl)
		}
	}
	cl, err := a.VerifyRequest(r.WithContext(ctx))
	if err != nil {
		return Claims{}, classify(r, err)
	}
	return cl, nil
}

// verifiedOf is verified claims' authkit/auth Verified request (see
// AuthenticateRequest for Can).
func verifiedOf(a Authenticator, cl Claims) (auth.Verified, error) {
	if err := credentialExpiry(cl); err != nil {
		return nil, err
	}
	i, ok := cl.Identity()
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	// A native authority has verified these claims and will re-check the
	// credential live. Expose the same sealed identity used by Can so trusted
	// account-ownership resolution does not have to trust exported metadata.
	// A standalone signature verifier and foreign resource tokens still carry
	// no native AuthKit authority.
	if _, native := a.(PermissionChecker); native {
		if bound, ok := boundIdentity(cl); ok {
			i = bound
		}
	}
	cl.Permissions = append([]string(nil), cl.Permissions...)
	id := identity{i, cl.Entitlements}
	if authority, ok := a.(Authority); ok {
		return sessionVerified{checkingVerified{id, cl, authority}, authority}, nil
	}
	if checker, ok := a.(PermissionChecker); ok {
		return checkingVerified{id, cl, checker}, nil
	}
	return id, nil
}

type identity struct {
	id           auth.Identity
	entitlements []string
}

func (p identity) Identity() auth.Identity { return p.id }

// Entitlements are the token's entitlements claim, its issuer's snapshot at
// mint; none for a credential without one (an API key).
func (p identity) Entitlements() []string { return slices.Clone(p.entitlements) }

type checkingVerified struct {
	identity
	claims  Claims
	checker PermissionChecker
}

var (
	_ auth.PermissionChecker       = checkingVerified{}
	_ auth.DirectPermissionChecker = checkingVerified{}
	_ auth.Bound                   = checkingVerified{}
)

// BoundScope is the group a credential is bound to (an API key's), as a
// scope of its group's issuer; zero for a person's own sign-in.
func (p checkingVerified) BoundScope() auth.Scope {
	if g := p.claims.Group; g != nil && g.GroupID != "" {
		return auth.Scope{Authority: g.AuthorityIssuer, ID: g.GroupID}
	}
	return auth.Scope{}
}

// CheckCredentialExpiry is the internal lifetime capability used by native
// source-account resolution. It preserves this verifier's original deadline.
func (p checkingVerified) CheckCredentialExpiry() error {
	return credentialExpiry(p.claims)
}

// Can checks the credential's authority in the group scope.ID names, live
// and without verifying the request again. The scope's authority must be the
// credential's own (the issuer of the groups it acts in). A revoked session
// is auth.ErrRevoked.
func (p checkingVerified) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	return p.can(ctx, scope, permission, false)
}

// CanDirect is Can without authority inherited from another scope.
func (p checkingVerified) CanDirect(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	return p.can(ctx, scope, permission, true)
}

func (p checkingVerified) can(ctx context.Context, scope auth.Scope, permission string, direct bool) (bool, error) {
	if err := credentialExpiry(p.claims); err != nil {
		return false, err
	}
	if scope.ID == "" || permission == "" || scope.Authority == "" || scope.Authority != authorityOf(p.claims) {
		return false, nil
	}
	identity, ok := boundIdentity(p.claims)
	if !ok {
		return false, nil
	}
	var allowed bool
	var err error
	if direct {
		checker, ok := p.checker.(DirectPermissionChecker)
		if !ok {
			return false, nil
		}
		allowed, err = checker.CanDirect(ctx, identity, iam.GroupByID(scope.ID), ident.Perm(permission))
	} else {
		allowed, err = p.checker.Can(ctx, identity, iam.GroupByID(scope.ID), ident.Perm(permission))
	}
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

// Refusal maps a failed verification of r onto the authkit/auth taxonomy,
// for an Authenticator that verifies r itself. A DPoP refusal is a
// *auth.Challenge carrying the headers DPoPChallenge writes
// (WWW-Authenticate, DPoP-Nonce).
func Refusal(r *http.Request, err error) error { return classify(r, err) }

// classify is Refusal.
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
	case errors.Is(err, iam.ErrAPIKeyRevoked), errors.Is(err, iam.ErrSessionRevoked):
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
	if err := credentialExpiry(p.claims); err != nil {
		return err
	}
	err := p.sessions.CheckRecentSignIn(ctx, p.claims)
	switch code := errmodel.CodeOf(err); {
	case err == nil:
		return nil
	case code == errmodel.CodeStepUpRequired:
		return stepUpChallenge(err)
	case errors.Is(err, iam.ErrSessionRevoked):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	case errors.Is(err, iam.ErrTokenExpired):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, err)
	case code == errmodel.CodeForbidden:
		return errors.Join(auth.ErrForbidden, err)
	default:
		return errors.Join(auth.ErrUnavailable, err)
	}
}

// Retained claims use the same wall clock and effective deadline as the JWT
// verifier. A live recheck does not verify or consume the sender proof again.
func credentialExpiry(cl Claims) error {
	if !cl.ValidUntil.IsZero() && time.Now().After(cl.ValidUntil) {
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, iam.ErrTokenExpired)
	}
	return nil
}

// stepUpChallenge is err, when it is step_up_required, as a authkit/auth
// step-up challenge: auth.ErrStepUpRequired with the error's max age and its
// metadata (the account's step-up methods). Nil for any other error.
func stepUpChallenge(err error) *auth.Challenge {
	maxAge, metadata, ok := errmodel.StepUp(err)
	if !ok {
		return nil
	}
	return &auth.Challenge{Err: errors.Join(auth.ErrStepUpRequired, err), MaxAge: maxAge, Metadata: metadata}
}
