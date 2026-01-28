package authhttp

import (
	"net/http"
	"strings"
	"time"
)

type userMeResponse struct {
	ID              string   `json:"id"`
	Email           *string  `json:"email"`
	PhoneNumber     *string  `json:"phone_number"`
	Username        string   `json:"username"`
	DiscordUsername *string  `json:"discord_username,omitempty"`
	EmailVerified   bool     `json:"email_verified"`
	PhoneVerified   bool     `json:"phone_verified"`
	HasPassword     bool     `json:"has_password"`
	Roles           []string `json:"roles"`
	Entitlements    []string `json:"entitlements"`
	Biography       *string  `json:"biography,omitempty"`
	CreatedAt       *string  `json:"created_at,omitempty"`
}

func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLUserMe) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, "unauthorized")
		return
	}

	adminUser, err := s.svc.AdminGetUser(r.Context(), claims.UserID)
	if err != nil || adminUser == nil {
		serverErr(w, "user_lookup_failed")
		return
	}

	username := ""
	if adminUser.Username != nil {
		username = strings.TrimSpace(*adminUser.Username)
	}
	if username == "" {
		username = strings.TrimSpace(claims.Username)
	}
	if username == "" {
		serverErr(w, "username_missing")
		return
	}

	hasPassword := s.svc.HasPassword(r.Context(), adminUser.ID)

	var createdAt *string
	if !adminUser.CreatedAt.IsZero() {
		formatted := adminUser.CreatedAt.UTC().Format(time.RFC3339)
		createdAt = &formatted
	}

	resp := userMeResponse{
		ID:              adminUser.ID,
		Email:           adminUser.Email,
		PhoneNumber:     adminUser.PhoneNumber,
		Username:        username,
		DiscordUsername: adminUser.DiscordUsername,
		EmailVerified:   adminUser.EmailVerified,
		PhoneVerified:   adminUser.PhoneVerified,
		HasPassword:     hasPassword,
		Roles:           adminUser.Roles,
		Entitlements:    adminUser.Entitlements,
		Biography:       adminUser.Biography,
		CreatedAt:       createdAt,
	}
	writeJSON(w, http.StatusOK, resp)
}
