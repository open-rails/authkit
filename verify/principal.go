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

// AuthenticateRequest is r's helpers/auth principal, identity only: a
// Verifier checks no permissions.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Principal, error) {
	return AuthenticateRequest(ctx, v, r)
}

// AuthenticateRequest is r's helpers/auth principal, for code written against
// helpers/auth providers. Behind a gate over a (Required, Optional,
// RequireSession, RequirePermission or Sensitive, in any adapter) it reuses
// the gate's verification, since verifying again would spend a DPoP proof
// twice; otherwise it verifies r through a. When a is a PermissionChecker
// (*authkit.Client), the principal's Can checks the credential's permissions
// live, the session included; otherwise it is identity only.
func AuthenticateRequest(ctx context.Context, a Authenticator, r *http.Request) (auth.Principal, error) {
	cl, err := authenticate(ctx, a, r)
	if err != nil {
		return nil, err
	}
	return principalOf(a, cl)
}

// AuthenticateSession is AuthenticateRequest plus RequireSession's session
// check, for identity-only code that must stop the moment a sign-in is
// revoked (billing, say): a credential minted from a sign-in (a user's token,
// or a delegated token AuthKit minted from one) is auth.ErrRevoked once it is
// revoked, and so is a delegated token AuthKit minted without one. Unlike
// RequireSession, a credential that carries no sign-in (an API key, a remote
// application's token or delegation) passes: verification already refuses it
// once revoked, and Can checks its authority live. Admitting only some kinds
// is the caller's policy (Principal.Identity().Kind).
func AuthenticateSession(ctx context.Context, a Authority, r *http.Request) (auth.Principal, error) {
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
	return principalOf(a, cl)
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
		return Claims{}, classify(err)
	}
	return cl, nil
}

// principalOf is verified claims' helpers/auth principal (see
// AuthenticateRequest for Can).
func principalOf(a Authenticator, cl Claims) (auth.Principal, error) {
	i, ok := cl.Identity()
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	cl.Permissions = append([]string(nil), cl.Permissions...)
	if checker, ok := a.(PermissionChecker); ok {
		return checkingPrincipal{identity{i}, cl, checker}, nil
	}
	return identity{i}, nil
}

type identity struct{ id auth.Identity }

func (p identity) Identity() auth.Identity { return p.id }

type checkingPrincipal struct {
	identity
	claims  Claims
	checker PermissionChecker
}

var _ auth.PermissionChecker = checkingPrincipal{}

// Can checks the credential's authority in the group scope.ID names, live
// and without verifying the request again. The scope's authority must be the
// credential's own (the issuer of the groups it acts in). A revoked session
// is auth.ErrRevoked.
func (p checkingPrincipal) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	if scope.ID == "" || permission == "" || scope.Authority == "" || scope.Authority != authorityOf(p.claims) {
		return false, nil
	}
	actor, ok := ActorFromClaims(p.claims)
	if !ok {
		return false, nil
	}
	allowed, err := p.checker.Can(ctx, actor, iam.GroupByID(scope.ID), ident.Perm(permission))
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

// classify maps a verification error onto the helpers/auth taxonomy.
func classify(err error) error {
	switch {
	case errors.Is(err, ErrSenderProofRequired):
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
