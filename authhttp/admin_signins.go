package authhttp

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

func (s *Service) handleAdminUserSigninsGET(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	events, err := s.svc.ListSessionEvents(r.Context(), userID, embedded.SessionEventCreated, embedded.SessionEventFailed)
	if err != nil {
		serverErr(w, authkit.CodeFailedToListSignins)
		return
	}

	resp := make([]map[string]any, 0, len(events))
	for _, e := range events {
		resp = append(resp, map[string]any{
			"occurred_at": e.OccurredAt,
			"issuer":      e.Issuer,
			"user_id":     e.UserID,
			"session_id":  e.SessionID,
			"event":       e.Event,
			"method":      e.Method,
			"reason":      e.Reason,
			"ip_addr":     e.IPAddr,
			"user_agent":  e.UserAgent,
		})
	}

	writeList(w, resp, "")
}
