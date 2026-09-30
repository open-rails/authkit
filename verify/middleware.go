package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Authenticator authenticates requests: a *Verifier, or an *authkit.Client,
// which also accepts its API keys and its remote applications' tokens.
type Authenticator interface {
	VerifyRequest(r *http.Request) (Claims, error)
}

// PermissionChecker checks an actor's authority in a group live;
// *authkit.Client is one. Can is false for an unknown group or an actor bound
// to another group, iam.ErrSessionRevoked once the actor's session is
// revoked, and iam.ErrUnknownPermission for an unregistered perm.
type PermissionChecker interface {
	Can(ctx context.Context, a iam.Actor, ref iam.GroupRef, perm iam.Perm) (bool, error)
	// KnownPermission reports whether perm is registered.
	KnownPermission(perm iam.Perm) bool
}

// SessionChecker checks the sign-in behind verified claims live;
// *authkit.Client is one. Both return nil or the error to answer:
// iam.ErrSessionRevoked, forbidden for a credential that carries no sign-in,
// or (CheckRecentSignIn) step_up_required carrying the step-up methods.
type SessionChecker interface {
	// CheckSession: the session or device key the token was minted from is
	// still active. A user's token carries one, and so does a delegated
	// token AuthKit minted from it.
	CheckSession(ctx context.Context, cl Claims) error
	// CheckRecentSignIn: CheckSession, and the user's own token, signed in
	// recently enough for a sensitive action, with the second factor when
	// the account has one.
	CheckRecentSignIn(ctx context.Context, cl Claims) error
}

// Authority authenticates requests and checks sessions and permissions live:
// what the live gates need. *authkit.Client is one.
type Authority interface {
	Authenticator
	PermissionChecker
	SessionChecker
}

// Required authenticates every request through a, storing its claims and
// actor in the request context, and answers 401 otherwise. It is stateless:
// a token outlives its revoked session until it expires. The live gates
// (RequireSession, RequirePermission, Sensitive) include it.
//
// Stacked gates over the same a verify a request once: the first stores the
// claims and the later ones reuse them, so a DPoP proof is spent and an API
// key looked up once. Claims another authenticator verified, or verified for
// another credential, or stored by SetClaims are verified again.
func Required(a Authenticator) func(http.Handler) http.Handler {
	mustAuthenticator(a)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !verifiedBy(r, a) {
				cl, err := a.VerifyRequest(r)
				if err != nil {
					writeAuthError(w, r, err)
					return
				}
				r = setVerified(r, a, cl)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Optional is Required when the request carries an Authorization header and
// passes it through anonymously otherwise. A present but invalid credential
// is refused.
func Optional(a Authenticator) func(http.Handler) http.Handler {
	required := Required(a)
	return func(next http.Handler) http.Handler {
		authenticated := required(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				next.ServeHTTP(w, r)
				return
			}
			authenticated.ServeHTTP(w, r)
		})
	}
}

// RequireSession is Required plus the session check: the session or device
// key the token was minted from is still active (not logged out, revoked,
// banned or deleted), or the request is 401 session_revoked. A user's token
// passes, and so does a delegated token AuthKit minted from a sign-in, while
// that sign-in stands; any other credential is 403 forbidden.
func RequireSession(a Authority) func(http.Handler) http.Handler {
	mustAuthenticator(a)
	return liveGate(a, a.CheckSession)
}

// Sensitive is RequireSession plus a recent sign-in of the user's own token:
// within the last 15 minutes, with the second factor when the account has
// one. A stale sign-in answers 403 step_up_required with the account's
// step-up methods, which auth-ui handles; a delegated token, which carries no
// sign-in of its own, is 403 forbidden. Stack it after RequirePermission when
// a route needs both.
func Sensitive(a Authority) func(http.Handler) http.Handler {
	mustAuthenticator(a)
	return liveGate(a, a.CheckRecentSignIn)
}

func liveGate(a Authority, check func(context.Context, Claims) error) func(http.Handler) http.Handler {
	required := Required(a)
	return func(next http.Handler) http.Handler {
		return required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, _ := ClaimsFromContext(r.Context())
			if err := check(r.Context(), cl); err != nil {
				iam.WriteError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// RequirePermission authenticates the request (it includes Required) and
// requires perm, checked live, in the group attached to the request
// (WithGroup, or an adapter's SetGroup). The check includes the token's
// session: once it is revoked the request is 401 session_revoked. A request
// with no group fails closed: 500 internal_error, logged with its route. It
// panics at construction on a perm a does not register.
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
	mustAuthenticator(a)
	if !a.KnownPermission(perm) {
		panic(fmt.Sprintf("authkit: RequirePermission: permission %q is not registered in any persona catalog", perm))
	}
	required := Required(a)
	return func(next http.Handler) http.Handler {
		return required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ref, ok := fixed, !fixed.IsZero()
			if !ok {
				ref, ok = r.Context().Value(groupKey{}).(iam.GroupRef)
				ok = ok && !ref.IsZero()
			}
			if !ok {
				route := r.Pattern
				if route == "" {
					route = r.Method + " " + r.URL.Path
				}
				slog.ErrorContext(r.Context(), "authkit: RequirePermission found no group on the request; attach one with verify.WithGroup or the adapter's SetGroup before it, or use RequirePermissionOn",
					"permission", perm.String(), "route", route)
				iam.WriteError(w, errmodel.E(errmodel.CodeInternalError))
				return
			}
			actor, ok := ActorFromContext(r.Context())
			if !ok {
				iam.WriteError(w, errmodel.E(errmodel.CodeForbidden))
				return
			}
			allowed, err := a.Can(r.Context(), actor, ref, perm)
			switch {
			case errors.Is(err, iam.ErrSessionRevoked):
				iam.WriteError(w, err)
			case err != nil || !allowed:
				iam.WriteError(w, errmodel.E(errmodel.CodeForbidden))
			default:
				next.ServeHTTP(w, r)
			}
		}))
	}
}

type groupKey struct{}

// WithGroup attaches the permission group a request acts in, for
// RequirePermission: the route's loader sets it once it has resolved the URL
// to its entity (a channel's group).
func WithGroup(ctx context.Context, ref iam.GroupRef) context.Context {
	return context.WithValue(ctx, groupKey{}, ref)
}

// mustAuthenticator panics on a nil authenticator: a route built without
// one is a programming error, caught when the route is built.
func mustAuthenticator(a Authenticator) {
	if a == nil {
		panic("authkit: middleware needs an authenticator (an *authkit.Client or a *verify.Verifier)")
	}
}

// writeAuthError answers a failed authentication: an AuthKit error keeps its
// code, anything else is 401 invalid_token.
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errDPoPProofRequired) || (isDPoPRequest(r) && errors.Is(err, ErrSenderProofRequired)) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
	}
	if errmodel.As(err) == nil {
		err = errmodel.E(errmodel.CodeInvalidToken, errmodel.WithCause(err))
	}
	iam.WriteError(w, err)
}
