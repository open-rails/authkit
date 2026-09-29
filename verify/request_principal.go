package verify

import (
	"context"
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/helpers/auth"
)

// WithPermissionChecker configures live scoped permission checks on the
// generic request principal. authorityIssuer identifies the checker's authority,
// not a value taken from the incoming credential. authkit.New wires its engine
// automatically; other hosts pass any PermissionChecker.
func (v *Verifier) WithPermissionChecker(checker PermissionChecker, authorityIssuer string) *Verifier {
	v.mu.Lock()
	v.permissionChecker, v.permissionAuthority = checker, strings.TrimSpace(authorityIssuer)
	v.mu.Unlock()
	return v
}

// AuthenticateRequest returns a provider-neutral principal for this request.
// It runs the complete VerifyRequest pipeline exactly once, including issuer,
// audience, assurance and sender-proof checks. It never trusts ambient context
// claims. Native account liveness remains deliberately lazy; use the explicit
// live variant for hosts whose admission policy requires an immediate check.
func (v *Verifier) AuthenticateRequest(ctx context.Context, r *http.Request) (auth.Principal, error) {
	if v == nil || r == nil {
		return nil, auth.ErrUnauthenticated
	}
	cl, err := v.VerifyRequest(r.WithContext(ctx))
	return v.requestPrincipal(cl, err)
}

// AuthenticateRequestLive applies the host's explicit live-account admission
// policy once, while retaining the same verified principal for later checks.
func (v *Verifier) AuthenticateRequestLive(ctx context.Context, r *http.Request) (auth.Principal, error) {
	if v == nil || r == nil {
		return nil, auth.ErrUnauthenticated
	}
	cl, err := v.VerifyRequestLive(r.WithContext(ctx))
	return v.requestPrincipal(cl, err)
}

// PrincipalFromVerifiedClaims explicitly hands off a request already verified
// by trusted host middleware. It does NOT authenticate claims or inspect request
// context. The caller must supply claims from complete request verification
// under its intended issuer, audience, assurance and sender-proof policy, for
// this same unchanged request, and apply any host admission policy first.
// Never call it with decoded tokens, request fields, or untrusted context data.
// The returned principal is valid only for that request. This trusted in-process
// boundary avoids verifying a single-use sender proof twice; AuthenticateRequest
// never performs this conversion implicitly from ambient context claims.
func (v *Verifier) PrincipalFromVerifiedClaims(cl Claims) (auth.Principal, error) {
	if v == nil {
		return nil, auth.ErrUnavailable
	}
	return v.requestPrincipal(cl, nil)
}

type requestPrincipal struct {
	identity  auth.Identity
	claims    Claims
	checker   PermissionChecker
	authority string
}

var _ auth.Principal = (*requestPrincipal)(nil)
var _ auth.PermissionChecker = (*requestPrincipal)(nil)

func (v *Verifier) requestPrincipal(cl Claims, err error) (auth.Principal, error) {
	if err != nil {
		return nil, requestAuthenticationError(err)
	}
	i, ok := cl.Identity()
	if !ok {
		return nil, auth.ErrUnauthenticated
	}
	// The permission ceiling is private and detached from backend-owned slices.
	cl.Permissions = append([]string(nil), cl.Permissions...)
	v.mu.RLock()
	p := &requestPrincipal{identity: i, claims: cl, checker: v.permissionChecker, authority: v.permissionAuthority}
	v.mu.RUnlock()
	return p, nil
}

func (p *requestPrincipal) Identity() auth.Identity { return p.identity }

// Can checks the captured credential's live authority in the group scope.ID
// names, without parsing the request or consuming sender proof again. The
// scope's authority must be the checker's own issuer.
func (p *requestPrincipal) Can(ctx context.Context, scope auth.Scope, permission string) (bool, error) {
	if scope.ID == "" || scope.Authority == "" || permission == "" {
		return false, nil
	}
	if p.checker == nil || p.authority == "" {
		return false, auth.ErrUnavailable
	}
	if scope.Authority != p.authority {
		return false, nil
	}
	allowed, err := Allow(ctx, p.checker, p.claims, ident.Perm(permission), iam.GroupByID(scope.ID))
	if err != nil {
		return false, errors.Join(auth.ErrUnavailable, err)
	}
	return allowed, nil
}

func requestAuthenticationError(err error) error {
	classification := auth.ErrUnauthenticated
	switch {
	case errors.Is(err, ErrSenderProofRequired):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrSenderProofRequired, err)
	case errors.Is(err, iam.ErrAPIKeyExpired), errors.Is(err, jwt.ErrTokenExpired):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrExpired, err)
	case errors.Is(err, iam.ErrAPIKeyRevoked):
		return errors.Join(auth.ErrUnauthenticated, auth.ErrRevoked, err)
	case errors.Is(err, ErrLivenessUnconfigured):
		classification = auth.ErrUnavailable
	default:
		if e, ok := iam.AsError(err); ok {
			switch {
			case e.Status() == http.StatusForbidden:
				classification = auth.ErrForbidden
			case e.Status() >= http.StatusInternalServerError:
				classification = auth.ErrUnavailable
			}
		}
	}
	return errors.Join(classification, err)
}
