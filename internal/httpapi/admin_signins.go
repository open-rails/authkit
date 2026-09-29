package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
)

// handleAdminUserSigninsGET pages an account's sign-ins and failed sign-ins,
// newest first (?cursor=, ?limit=).
func (s *Service) handleAdminUserSigninsGET(w http.ResponseWriter, r *http.Request) {
	page, err := s.svc.SessionEvents(r.Context(), r.PathValue("user_id"), iam.SessionEventQuery{
		Kinds: []iam.SessionEventKind{iam.SessionEventCreated, iam.SessionEventFailed},
		Page:  pageQuery(r),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, page.Items, page.Next)
}
