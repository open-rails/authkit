package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

func (s *Service) handleAdminUserSigninsGET(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	events, err := s.svc.ListSessionEvents(r.Context(), userID, authflow.SessionEventCreated, authflow.SessionEventFailed)
	if err != nil {
		serverErr(w, iam.CodeFailedToListSignins, err)
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
