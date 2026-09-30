package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// handleAdminUserSessionEventsGET pages an account's session history, newest
// first (?kind= repeatable, every kind when absent; ?cursor=, ?limit=).
func (s *Service) handleAdminUserSessionEventsGET(w http.ResponseWriter, r *http.Request) {
	q, ok := readSessionEventQuery(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListSessionEvents(r.Context(), r.PathValue("user_id"), q)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}

// readSessionEventQuery reads a session history's query: an unknown kind is
// 400 on param kind.
func readSessionEventQuery(w http.ResponseWriter, r *http.Request) (iam.SessionEventQuery, bool) {
	var query SessionEventQuery
	if !readQuery(w, r, &query) {
		return iam.SessionEventQuery{}, false
	}
	page, err := query.Page()
	if err != nil {
		writeError(w, err)
		return iam.SessionEventQuery{}, false
	}
	q := iam.SessionEventQuery{Page: page}
	for _, k := range query.Kind {
		switch kind := iam.SessionEventKind(k); kind {
		case iam.SessionEventCreated, iam.SessionEventFailed, iam.SessionEventRevoked, iam.SessionEventPasswordChange,
			iam.SessionEventPasswordRecovery, iam.SessionEventAccountSessionsRevoked:
			q.Kinds = append(q.Kinds, kind)
		default:
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("kind"))
			return iam.SessionEventQuery{}, false
		}
	}
	return q, true
}
