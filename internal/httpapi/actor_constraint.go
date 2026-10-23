package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/internal/actorconstraint"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// requireExpectedActor runs after request authentication. A client may constrain
// which authenticated actor it expects, but this header never supplies identity,
// credential state, permissions, tenant dispatch or delegated authority.
func requireExpectedActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(actorconstraint.Header)
		who, ok := verify.IdentityFromContext(r.Context())
		if !ok || len(values) != 1 || !actorconstraint.Matches(values[0], who) {
			fail(w, errmodel.CodeForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
