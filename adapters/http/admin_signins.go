package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleAdminUserSigninsGET(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, "invalid_request")
		return
	}
	if s.authlogr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "authlog_unavailable"})
		return
	}

	events, err := s.authlogr.ListSessionEvents(r.Context(), userID, core.SessionEventCreated, core.SessionEventFailed)
	if err != nil {
		serverErr(w, "failed_to_list_signins")
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

	writeJSON(w, http.StatusOK, map[string]any{
		"data": resp,
	})
}
