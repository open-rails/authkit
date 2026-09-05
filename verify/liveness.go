package verify

import (
	"context"
	"errors"
	"net/http"

	authkit "github.com/open-rails/authkit"
)

// LivenessSource resolves account liveness — and the identity fields that are
// fresh as of that same lookup — for verified user principals (#267).
// authkit.Client satisfies it, embedded or remote, so wiring is
// `v.WithLiveness(client)`; verify declares the port rather than importing the
// engine, exactly as it does for PermissionChecker.
type LivenessSource interface {
	UserLivenessByIDs(ctx context.Context, ids []string) (map[string]authkit.UserLiveness, error)
}

// ErrLivenessUnconfigured is returned by VerifyRequestLive when no
// LivenessSource is wired. It is NOT an authError: a missing source is a host
// wiring mistake, not a bad credential, and conflating the two would let a
// deployment that cannot check liveness look like one where every user is
// banned. RequiredLive refuses at construction so this can only be reached by
// an out-of-band caller.
var ErrLivenessUnconfigured = errors.New("verify: liveness gate used without a LivenessSource (call Verifier.WithLiveness)")

// WithLiveness wires the account-liveness backend used by VerifyRequestLive and
// the RequiredLive middlewares. Pass the authkit.Client the host already holds.
func (v *Verifier) WithLiveness(src LivenessSource) *Verifier {
	v.mu.Lock()
	v.liveness = src
	v.mu.Unlock()
	return v
}

// livenessSource reads the wired source under the verifier lock.
func (v *Verifier) livenessSource() LivenessSource {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.liveness
}

// HasLiveness reports whether a LivenessSource is wired. Hosts that mount a
// liveness-gated route set conditionally can assert this at boot instead of
// discovering the gap on the first request.
func (v *Verifier) HasLiveness() bool { return v.livenessSource() != nil }

// VerifyRequestLive is VerifyRequest plus a per-request account-liveness gate:
// the stateful twin of the deliberately stateless default (#215/#267).
//
// It exists because the stateless path leaves a banned or deleted user holding
// a syntactically valid token until it expires, and every privileged host
// surface was hand-rolling the same gate around VerifyRequest to close that
// window — one of them calling the ADMIN directory per request just to refresh
// a username and email onto the claims. Both of those are this method's job now.
//
// Behaviour:
//
//   - Everything VerifyRequest enforces (bearer parse, API-key resolution, JWT
//     verify, 2FA gates, the delegated issuer gate) runs first, unchanged.
//   - Only NATIVE USER principals are liveness-checked. An API key resolves its
//     secret live on every request already, and a delegated principal is gated
//     on its remote application being enabled; neither carries a UserID, and
//     inventing a lookup for them would be a second gate, not a stronger one.
//   - FAIL-CLOSED is the only posture. A lookup error, an id the directory does
//     not return, or a not-Allowed verdict all deny with 401. There is no option
//     to fall back to the stateless answer: a gate that opens when its dependency
//     is down is not a gate.
//   - The returned Claims carry the FRESH Username, Email and EmailVerified
//     from that same lookup, overwriting whatever the token minted — including
//     overwriting with empty, which is the honest answer for a user who cleared
//     the field. This is what makes a host's per-request AdminGetUser call
//     deletable. Roles and entitlements are deliberately NOT re-enriched here:
//     they already have live reads of their own (RoleSlugsByUsers, Allow,
//     ListEntitlements) and a second copy would be the duplication this issue
//     is removing, not another one of it.
//
// CACHING CONTRACT: none. Exactly one UserLivenessByIDs call per gated request,
// no memoization, no negative cache. That is not a regression — the hosts this
// replaces each did one lookup per request — and it is the only version of the
// contract that can be stated honestly, because any cache reintroduces exactly
// the stale-authorization window the gate exists to close. A deployment that
// decides it wants that trade implements LivenessSource itself and owns the
// staleness window explicitly, rather than inheriting one from a library
// default.
//
// Compose with permission checks rather than duplicating them: this answers
// "is this account live", RequirePermission/Allow answer "may it do this".
func (v *Verifier) VerifyRequestLive(r *http.Request) (Claims, error) {
	// Checked BEFORE the credential, deliberately: an unconfigured gate is a
	// wiring bug whose report must not depend on what the request happened to
	// carry, and must never be mistakable for a credential failure.
	if !v.HasLiveness() {
		return Claims{}, ErrLivenessUnconfigured
	}
	cl, err := v.VerifyRequest(r)
	if err != nil {
		return Claims{}, err
	}
	live, l, err := v.IsLive(r.Context(), cl)
	switch {
	case errors.Is(err, ErrLivenessUnconfigured):
		return Claims{}, err
	case err != nil:
		return Claims{}, &authError{http.StatusUnauthorized, "liveness_unavailable"}
	case !live:
		return Claims{}, &authError{http.StatusUnauthorized, "account_disabled"}
	}
	// Machine and delegated principals carry no UserID and no user row; there is
	// nothing fresh to write onto their claims.
	if cl.UserID == "" {
		return cl, nil
	}
	cl.Username = l.Username
	cl.Email = l.Email
	cl.EmailVerified = l.EmailVerified
	return cl, nil
}

// IsLive reports whether cl's principal is a live account, and returns the
// fresh identity fields alongside the verdict. It is the programmatic predicate
// behind VerifyRequestLive, for gates that already hold verified Claims and are
// not driving an HTTP pipeline.
//
// Non-user principals (no UserID) are live by definition here — their liveness
// lives on their own credential — and come back with a zero UserLiveness.
// Fail-closed: an error, or an id the directory does not return, is false.
func (v *Verifier) IsLive(ctx context.Context, cl Claims) (bool, authkit.UserLiveness, error) {
	src := v.livenessSource()
	if src == nil {
		return false, authkit.UserLiveness{}, ErrLivenessUnconfigured
	}
	if cl.UserID == "" {
		return true, authkit.UserLiveness{}, nil
	}
	live, err := src.UserLivenessByIDs(ctx, []string{cl.UserID})
	if err != nil {
		return false, authkit.UserLiveness{}, err
	}
	l, ok := live[cl.UserID]
	if !ok || !l.Allowed {
		return false, authkit.UserLiveness{}, nil
	}
	return true, l, nil
}

// AllowLive is Allow with the account-liveness precondition: "this account is
// live AND holds perm", in one call.
//
// It exists because both consumer hosts had independently written that
// conjunction by hand, each bolting a liveness lookup in front of
// verify.Allow — two gates a caller could get out of order, or forget one half
// of. A banned user who still holds a permission assignment must be denied, and
// that ordering is now the library's to guarantee, not the host's to remember.
//
// Fail-closed throughout: a liveness error, a dead account, or a Can error all
// deny (the error is returned; callers must deny on a non-nil error).
func (v *Verifier) AllowLive(ctx context.Context, checker PermissionChecker, cl Claims, perm string, scope PermissionScope) (bool, error) {
	live, _, err := v.IsLive(ctx, cl)
	if err != nil || !live {
		return false, err
	}
	return Allow(ctx, checker, cl, perm, scope)
}

// RequiredLive is Required with the per-request account-liveness gate: a banned
// or deleted user is rejected on their NEXT request instead of at token expiry,
// and the downstream handler reads fresh identity claims.
//
// It returns ErrLivenessUnconfigured when no LivenessSource is wired. A gate
// that cannot perform its check is a boot-time configuration error, refused
// before it reaches the route table rather than degraded to a weaker gate that
// looks like the stronger one.
func RequiredLive(v *Verifier) (func(http.Handler) http.Handler, error) {
	if v == nil || !v.HasLiveness() {
		return nil, ErrLivenessUnconfigured
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := v.VerifyRequestLive(r)
			if err != nil {
				var ae *authError
				if errors.As(err, &ae) && ae.status == http.StatusForbidden {
					forbidden(w, ae.reason)
				} else {
					unauthorized(w, err.Error())
				}
				return
			}
			r = r.WithContext(SetClaims(r.Context(), cl))
			next.ServeHTTP(w, r)
		})
	}, nil
}

// RequiredLiveUser is RequiredLive restricted to native human users: machine and
// delegated principals are rejected rather than passed through unchecked. Use it
// on a route whose whole premise is "a live human did this".
func RequiredLiveUser(v *Verifier) (func(http.Handler) http.Handler, error) {
	req, err := RequiredLive(v)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return req(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil || !cl.IsUser() {
				unauthorized(w, "invalid_principal")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}, nil
}
