package authhttp

import (
	"errors"
	"net/http"

	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/verify"
)

// handleUserMeGET: the profile projection is authcore.UserProfile (ak#318);
// the transport contributes only what the verified claims and the provider
// registry know.
func (s *Service) handleUserMeGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	profile, err := s.svc.UserProfile(r.Context(), authcore.ProfileInput{
		UserID:                 claims.UserID,
		ClaimsUsername:         claims.Username,
		AuthTime:               claims.AuthTime,
		StepUpSatisfied:        verify.SensitiveClaims(claims),
		EnabledProviders:       s.providerNames(),
		ProviderSupportsStepUp: s.providerSupportsStepUp,
	})
	if err != nil {
		var fe *authcore.FlowError
		if errors.As(err, &fe) && fe.Stage == "load_user" {
			serverErr(w, ErrUserLookupFailed)
			return
		}
		serverErr(w, ErrDatabaseError)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Service) providerSupportsStepUp(name string) bool {
	p, ok := s.provider(name)
	return ok && p.SupportsStepUp()
}
