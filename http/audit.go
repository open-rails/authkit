package authhttp

import "net/http"

func logLoginFailed(s *Service, r *http.Request, userID string, reason string) {
	if s == nil || s.svc == nil {
		return
	}
	ua := r.UserAgent()
	ip := clientIP(r)
	s.svc.LogSessionFailed(r.Context(), userID, "", &reason, &ip, &ua)
}
