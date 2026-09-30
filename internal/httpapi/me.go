package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// The caller's own account: GET/PATCH/DELETE /me, GET /me/security and
// DELETE /me/providers/{provider}. The profile projection is the engine's
// (ak#318); the transport adds what the verified claims and the provider
// registry know.

func (s *Service) handleMeGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	s.writeProfile(w, r, claims)
}

// handleMePATCH changes the caller's username, preferred language and avatar
// in one UpdateUser call (the rename policy applies) and answers the profile.
func (s *Service) handleMePATCH(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	actor, hasActor := verify.ActorFromContext(r.Context())
	if !ok || !hasActor || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var body ProfileUpdateRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	update := iam.UserUpdate{AvatarURL: body.AvatarURL}
	if body.Username != nil {
		name := strings.TrimSpace(*body.Username)
		if name == "" {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("username"))
			return
		}
		update.Username = &name
	}
	if body.PreferredLanguage != nil {
		language, err := authflow.NormalizePreferredLanguage(strings.TrimSpace(*body.PreferredLanguage))
		if err != nil || !acceptable(s.cfg.Languages, language) {
			fail(w, errmodel.CodeInvalidPreferredLanguage)
			return
		}
		update.PreferredLanguage = &language
	}
	if _, err := s.svc.UpdateUser(r.Context(), actor, claims.UserID, update); err != nil {
		writeError(w, err)
		return
	}
	s.writeProfile(w, r, claims)
}

func (s *Service) handleMeSecurityGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	security, err := s.svc.UserSecurity(r.Context(), s.profileInput(claims))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, security)
}

// handleMeDELETE deletes the caller's own account (restorable until purge);
// the route requires a recent sign-in.
func (s *Service) handleMeDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	actor, hasActor := verify.ActorFromContext(r.Context())
	if !ok || !hasActor || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	res, err := s.svc.DeleteUsers(r.Context(), actor, []string{claims.UserID})
	if err := opErr(res, err); err != nil {
		if errmodel.As(err) == nil {
			serverErr(w, "failed_to_delete", err)
			return
		}
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleMeProviderDELETE unlinks a provider unless it is the caller's last way
// to sign in; the route requires a recent sign-in.
func (s *Service) handleMeProviderDELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		fail(w, errmodel.CodeInvalidProvider)
		return
	}
	removed, err := s.svc.UnlinkProviderUnlessLast(r.Context(), claims.UserID, provider)
	if err != nil {
		serverErr(w, "failed_to_unlink", err)
		return
	}
	if !removed {
		fail(w, errmodel.CodeCannotUnlinkLastLoginMethod)
		return
	}
	noContent(w)
}

// writeProfile answers the caller's UserProfile.
func (s *Service) writeProfile(w http.ResponseWriter, r *http.Request, claims verify.Claims) {
	profile, err := s.svc.UserProfile(r.Context(), s.profileInput(claims))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Service) profileInput(claims verify.Claims) authflow.ProfileInput {
	return authflow.ProfileInput{
		UserID:                 claims.UserID,
		ClaimsUsername:         claims.Username,
		AuthTime:               claims.AuthTime,
		StepUpSatisfied:        authflow.RecentSignIn(claims.AuthTime, claims.AMR, claims.MFAEnrolled, time.Now()),
		AuthMethods:            claims.AMR,
		ProviderSupportsStepUp: s.providerSupportsStepUp,
	}
}

func (s *Service) providerSupportsStepUp(name string) bool {
	p, ok := s.provider(name)
	return ok && p.SupportsStepUp()
}

