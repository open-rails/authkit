package verify

import (
	"context"
	"fmt"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// PermissionChecker checks an actor's live authority in a group; *authkit.Auth
// is one. Can is false for a dead actor, an unknown group or an actor bound
// to another group, and ErrUnknownPermission for an unregistered perm.
type PermissionChecker interface {
	Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error)
	// KnownPermission reports whether perm is registered in the checker's
	// permission catalogs.
	KnownPermission(perm iam.Perm) bool
}

// Authority authenticates requests and checks permissions: what
// RequirePermission needs. *authkit.Auth is one.
type Authority interface {
	PermissionChecker
	Verifier() *Verifier
}

// PermissionScope is a credential's permission-group binding: the group id,
// the issuer whose group it is, and the group's persona.
type PermissionScope struct {
	GroupID         string
	AuthorityIssuer string
	Persona         iam.Persona
}

// MustKnowPermission panics when checker does not register perm: gating a
// route on an unregistered permission is a programming error, caught when the
// route is built.
func MustKnowPermission(checker PermissionChecker, perm iam.Perm) {
	if !checker.KnownPermission(perm) {
		panic(fmt.Sprintf("authkit: RequirePermission: permission %q is not registered in any persona catalog", perm))
	}
}

// Allow reports whether the actor verified claims act as holds perm in the
// group ref addresses, checked live by checker. Claims carrying no AuthKit
// authority, a nil checker and a zero ref are refused.
func Allow(ctx context.Context, checker PermissionChecker, cl Claims, perm iam.Perm, ref iam.GroupRef) (bool, error) {
	actor, ok := ActorFromClaims(cl)
	if !ok || checker == nil || ref.IsZero() {
		return false, nil
	}
	return checker.Can(ctx, actor, ref, perm)
}

// RequirePermission authenticates the request (it includes Required; do not
// stack Required in front of it) and requires perm, checked live, in the group
// resolve returns for the request. A nil resolve means the root group. It
// panics at construction on a perm the authority does not register.
func RequirePermission(a Authority, perm iam.Perm, resolve func(*http.Request) iam.GroupRef) func(http.Handler) http.Handler {
	MustKnowPermission(a, perm)
	if resolve == nil {
		resolve = func(*http.Request) iam.GroupRef { return iam.RootGroup() }
	}
	authenticate := Required(a.Verifier())
	return func(next http.Handler) http.Handler {
		gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil {
				fail(w, errmodel.CodeForbidden)
				return
			}
			ok, err := Allow(r.Context(), a, cl, perm, resolve(r))
			if err != nil || !ok {
				fail(w, errmodel.CodeForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
		return authenticate(gate)
	}
}
