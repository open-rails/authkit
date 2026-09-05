package authhttp

import (
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/verify"
)

// handleUserMeGET: the profile projection is embedded.UserProfile (ak#318);
// the transport contributes only what the verified claims and the provider
// registry know.
func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeUnauthorized)
		return
	}
	profile, err := s.svc.UserProfile(r.Context(), embedded.ProfileInput{
		UserID:                 claims.UserID,
		ClaimsUsername:         claims.Username,
		AuthTime:               claims.AuthTime,
		StepUpSatisfied:        verify.SensitiveClaims(claims),
		EnabledProviders:       s.providerNames(),
		ProviderSupportsStepUp: s.providerSupportsStepUp,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Service) providerSupportsStepUp(name string) bool {
	p, ok := s.provider(name)
	return ok && p.SupportsStepUp()
}
