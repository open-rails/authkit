package verify

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// PermissionChecker checks an actor's live authority in a group; *authkit.Client
// is one. Can is false for a dead actor, an unknown group or an actor bound
// to another group, and ErrUnknownPermission for an unregistered perm.
type PermissionChecker interface {
	Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error)
	// KnownPermission reports whether perm is registered in the checker's
	// permission catalogs.
	KnownPermission(perm iam.Perm) bool
}

// VerifierSource is what request middleware authenticates with: an
// *authkit.Client, or a *Verifier itself.
type VerifierSource interface {
	Verifier() *Verifier
}

// Verifier is v, so a bare Verifier is a VerifierSource.
func (v *Verifier) Verifier() *Verifier { return v }

// Authority authenticates requests and checks permissions: what
// RequirePermission needs. *authkit.Client is one.
type Authority interface {
	PermissionChecker
	VerifierSource
}

type groupCtxKey struct{}

// WithGroup attaches the permission group a request acts in, for
// RequirePermission: the app's route loader sets it once it has resolved the
// URL to its entity (a channel's group).
func WithGroup(ctx context.Context, ref iam.GroupRef) context.Context {
	return context.WithValue(ctx, groupCtxKey{}, ref)
}

// GroupFromContext is the group WithGroup attached.
func GroupFromContext(ctx context.Context) (iam.GroupRef, bool) {
	ref, ok := ctx.Value(groupCtxKey{}).(iam.GroupRef)
	return ref, ok && !ref.IsZero()
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
// attached to the request (WithGroup, or an adapter's SetGroup). A request
// with no group fails closed: 500 internal_error, logged with its route. It
// panics at construction on a perm the authority does not register.
func RequirePermission(a Authority, perm iam.Perm) func(http.Handler) http.Handler {
	return requirePermission(a, perm, iam.GroupRef{})
}

// RequirePermissionOn is RequirePermission in one fixed group, such as
// iam.RootGroup().
func RequirePermissionOn(a Authority, ref iam.GroupRef, perm iam.Perm) func(http.Handler) http.Handler {
	if ref.IsZero() {
		panic("authkit: RequirePermissionOn: the zero GroupRef addresses no group")
	}
	return requirePermission(a, perm, ref)
}

func requirePermission(a Authority, perm iam.Perm, fixed iam.GroupRef) func(http.Handler) http.Handler {
	MustKnowPermission(a, perm)
	authenticate := Required(a.Verifier())
	return func(next http.Handler) http.Handler {
		gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ref, ok := fixed, !fixed.IsZero()
			if !ok {
				ref, ok = GroupFromContext(r.Context())
			}
			if !ok {
				route := r.Pattern
				if route == "" {
					route = r.Method + " " + r.URL.Path
				}
				slog.ErrorContext(r.Context(), "authkit: RequirePermission found no group on the request; attach one with verify.WithGroup or the adapter's SetGroup before it, or use RequirePermissionOn",
					"permission", perm.String(), "route", route)
				fail(w, errmodel.CodeInternalError)
				return
			}
			cl, err := GetClaims(r.Context())
			if err != nil {
				fail(w, errmodel.CodeForbidden)
				return
			}
			allowed, err := Allow(r.Context(), a, cl, perm, ref)
			if err != nil || !allowed {
				fail(w, errmodel.CodeForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
		return authenticate(gate)
	}
}
