package verify

import (
	"context"
	"errors"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// AuthenticateRequest verifies r and returns its helpers/auth principal,
// identity only: a Verifier checks no permissions.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Principal, error) {
	return AuthenticateRequest(ctx, v, r)
}

// AuthenticateRequest verifies r through a and returns its helpers/auth
// principal, for code written against helpers/auth providers. When a is a
// PermissionChecker (*authkit.Client), the principal's Can checks the
// credential's permissions live, the session included; otherwise it is
// identity only.
func AuthenticateRequest(ctx context.Context, a Authenticator, r *http.Request) (auth.Principal, error) {
	if a == nil || r == nil {
		return nil, auth.ErrUnauthenticated
	}
	cl, err := a.VerifyRequest(r.WithContext(ctx))
	if err != nil {
		return nil, classify(err)
	}
	return PrincipalFromClaims(a, cl)
}

// PrincipalFromClaims hands claims a trusted middleware verified for this
// same request to helpers/auth code without verifying again, which would
// spend a single-use sender proof twice. Never pass claims from anywhere
// else. See AuthenticateRequest for Can.
func PrincipalFromClaims(a Authenticator, cl Claims) (auth.Principal, error) {
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
