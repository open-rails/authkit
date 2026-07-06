package verify

import (
	"context"
	"net/http"
)

// PermissionChecker evaluates whether a subject holds a permission within a
// permission-group instance — the server-side authorization primitive. The
// embedded engine (`embedded.Client` / the root `authkit.Client`, which expose
// `Can`) satisfy this directly; verify declares the port so it never imports the
// engine (verify is jwt-only).
type PermissionChecker interface {
	Can(ctx context.Context, subjectID, subjectKind, persona, instanceSlug, perm string) (bool, error)
}

// PermissionScope is the permission-group instance a request's authority is
// evaluated against. For a singleton persona (e.g. `root`) Instance is "".
type PermissionScope struct {
	Persona  string
	Instance string
}

// subjectKindUser is the subject-kind discriminator for an authenticated human
// user. Mirrors embedded.SubjectKindUser (a stable stored value); verify cannot
// import embedded, and the gate only reaches Can for human users (machine
// principals are handled by the token-carried branch below), so it is fixed here.
const subjectKindUser = "user"

// Allow reports whether cl holds perm — the programmatic authorization predicate
// behind RequirePermission, for non-HTTP gates (e.g. a host's billing-admin check).
// Two authority paths, matching how authkit carries it:
//   - API-key / delegated-access principals carry their permission strings ON the
//     token; those are checked directly (no group lookup). A GROUP-BOUND machine
//     principal (#248: API keys, remote-application tokens) is additionally
//     required to match `scope` EXACTLY — its authority is valid only on the
//     group instance it was minted on. Unbound tokens (delegated, by contract)
//     are unrestricted here.
//   - Human users carry only identity; their authority is resolved against the
//     registered permission-group schema via the checker's Can in `scope`.
//
// Fail-closed: a token without the perm, a bound principal in a mismatched
// scope, a nil checker, or an empty UserID yields false; a Can error is
// returned (the caller must deny on a non-nil error).
func Allow(ctx context.Context, checker PermissionChecker, cl Claims, perm string, scope PermissionScope) (bool, error) {
	if cl.HasPermission(perm) && cl.PermissionGroupAllows(scope.Persona, scope.Instance) {
		return true, nil
	}
	if checker == nil || cl.UserID == "" {
		return false, nil
	}
	return checker.Can(ctx, cl.UserID, subjectKindUser, scope.Persona, scope.Instance, perm)
}

// RequirePermission gates a handler on `perm`, evaluated server-side via the
// PermissionChecker in the scope `resolve` derives from the request — so one gate
// serves a singleton persona (`root`) AND resource-scoped personas
// (`/v1/merchants/{id}/...` → {Persona: "merchant", Instance: id}). It must run
// after Required so the verified Claims are in context. The authority decision is
// Allow; this is the HTTP wrapper.
//
// Fail-closed: missing claims, no resolver, an unknown group, a Can error, or
// a group-bound machine principal (#248) whose request scope cannot be resolved
// or does not match its owning group instance all deny (403).
func RequirePermission(checker PermissionChecker, perm string, resolve func(*http.Request) PermissionScope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil {
				forbidden(w, "forbidden")
				return
			}
			// Token-carried authority short-circuits without a scope ONLY for
			// unbound principals (delegated access — issuer trust + permissions).
			// A group-bound machine principal (#248) needs the resolved scope to
			// check its instance binding, so it falls through to Allow.
			if cl.HasPermission(perm) && !cl.BoundToPermissionGroup() {
				next.ServeHTTP(w, r)
				return
			}
			if resolve == nil {
				forbidden(w, "forbidden")
				return
			}
			ok, err := Allow(r.Context(), checker, cl, perm, resolve(r))
			if err != nil || !ok {
				forbidden(w, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
