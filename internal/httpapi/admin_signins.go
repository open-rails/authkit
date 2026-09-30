package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
)

// handleAdminUserSigninsGET pages an account's sign-ins and failed sign-ins,
// newest first (?cursor=, ?limit=).
func (s *Service) handleAdminUserSigninsGET(w http.ResponseWriter, r *http.Request) {
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListSessionEvents(r.Context(), r.PathValue("user_id"), iam.SessionEventQuery{
		Kinds: []iam.SessionEventKind{iam.SessionEventCreated, iam.SessionEventFailed},
		Page:  p,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}
