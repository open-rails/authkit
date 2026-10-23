package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleEventsGET(w http.ResponseWriter, r *http.Request) {
	var query EventQuery
	if !readQuery(w, r, &query) {
		return
	}
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	// The log exposes the same private account facts as the user directory.
	// Authority mode never falls back to a tenant grant. Selecting a tenant
	// comes from trusted dispatch, not from data inside the cursor.
	allowed, err := s.svc.Can(r.Context(), who, iam.RootGroup(), ident.RootUsersRead)
	if err == nil && !allowed && !query.Authority {
		tenant, scopeErr := s.svc.AccountScope(r.Context())
		if scopeErr != nil {
			err = scopeErr
		} else {
			allowed, err = s.svc.Can(r.Context(), who, tenant, ident.Perm("tenant:users:read"))
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	if !allowed {
		fail(w, errmodel.CodeForbidden)
		return
	}
	q := iam.EventQuery{After: query.After, Authority: query.Authority}
	if query.Limit != nil {
		q.Limit = *query.Limit
		if q.Limit == 0 {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("limit"))
			return
		}
	}
	for _, raw := range query.Kind {
		for _, kind := range strings.Split(raw, ",") {
			q.Kinds = append(q.Kinds, iam.EventKind(strings.TrimSpace(kind)))
		}
	}
	page, err := s.svc.ListEvents(r.Context(), q)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
