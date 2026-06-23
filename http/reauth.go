package authhttp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/internal/db"
	oidckit "github.com/open-rails/authkit/oidc"
)

func ptr(s string) *string { return &s }

func (s *Service) handlePasswordReauthPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil || body.Password == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, body.Password); verr != nil {
		if errors.Is(verr, core.ErrPasswordResetRequired) {
			// The stored hash can never verify (legacy reset-required); the user
			// cannot reauth with a password and must reset it first.
			unauthorized(w, ErrPasswordResetRequired)
			return
		}
		unauthorized(w, ErrInvalidPassword)
		return
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
		serverErr(w, ErrReauthFailed)
		return
	}
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"fresh_auth": sessionFreshnessResponse(freshness),
	})
}

func (s *Service) handleOIDCReauthStartPOST(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimSpace(r.PathValue("provider"))
	if cfg, ok := s.oauth2Provider(provider); ok {
		s.handleOAuthReauthStartPOST(w, r, cfg.Name)
		return
	}
	if s.rateLimited(w, r, RLOIDCStart) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" || strings.TrimSpace(claims.SessionID) == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}

	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = decodeJSON(r, &body)

	manager := s.oidcManager()
	issuer, ok := manager.IssuerFor(provider)
	if !ok || strings.TrimSpace(issuer) == "" {
		badRequest(w, ErrUnknownProvider)
		return
	}
	if !s.userHasLinkedIssuerProvider(r, claims.UserID, issuer, provider) {
		badRequest(w, ErrProviderNotLinked)
		return
	}

	state := randB64(32)
	nonce := randB64(16)
	verifier := ""
	challenge := ""
	if pc, ok := manager.Provider(provider); ok && pc.PKCE {
		var err error
		verifier, challenge, err = oidckit.GeneratePKCE()
		if err != nil {
			serverErr(w, ErrPKCEGenerationFailed)
			return
		}
	}
	redirectURI := buildRedirectURI(r, provider)
	authURL, err := manager.Begin(r.Context(), provider, state, nonce, challenge, redirectURI)
	if err != nil {
		badRequest(w, ErrOIDCBeginFailed)
		return
	}
	if err := s.stateCache().Put(r.Context(), state, oidckit.StateData{
		Provider:        provider,
		Verifier:        verifier,
		Nonce:           nonce,
		RedirectURI:     redirectURI,
		ReauthUserID:    claims.UserID,
		ReauthSessionID: claims.SessionID,
		ReauthReturnTo:  sanitizeReauthReturnTo(body.ReturnTo),
	}); err != nil {
		serverErr(w, ErrStateStoreFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"auth_url": authURL, "state": state})
}

func (s *Service) userHasLinkedIssuerProvider(r *http.Request, userID, issuer, provider string) bool {
	pg := s.svc.Postgres()
	if pg == nil {
		return false
	}
	exists, err := db.New(db.ForSchema(pg, s.svc.Schema())).UserProviderLinkExists(r.Context(), db.UserProviderLinkExistsParams{
		UserID:       strings.TrimSpace(userID),
		Issuer:       strings.TrimSpace(issuer),
		ProviderSlug: ptr(strings.TrimSpace(provider)),
	})
	return err == nil && exists
}

func (s *Service) completeOIDCReauth(w http.ResponseWriter, r *http.Request, sd oidckit.StateData, provider, issuer, subject string) bool {
	if strings.TrimSpace(sd.ReauthUserID) == "" {
		return false
	}
	userID, _, err := s.svc.GetProviderLinkByIssuer(r.Context(), issuer, subject)
	if err != nil || userID != sd.ReauthUserID {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if err := s.svc.MarkSessionAuthenticated(r.Context(), sd.ReauthUserID, sd.ReauthSessionID); err != nil {
		redirectReauthResult(w, r, sd.ReauthReturnTo, "failed")
		return true
	}
	if strings.EqualFold(r.URL.Query().Get("format"), "json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		freshness, _ := s.svc.SessionFreshness(r.Context(), sd.ReauthUserID, sd.ReauthSessionID, time.Now())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "fresh_auth": sessionFreshnessResponse(freshness), "provider": provider})
		return true
	}
	redirectReauthResult(w, r, sd.ReauthReturnTo, "success")
	return true
}

func (s *Service) requireFreshAuthOrPassword(w http.ResponseWriter, r *http.Request, claims Claims, password string) bool {
	if _, err := s.svc.RequireFreshSession(r.Context(), claims.UserID, claims.SessionID, time.Now()); err == nil {
		return true
	} else if !errors.Is(err, core.ErrReauthenticationRequired) {
		unauthorized(w, ErrNotAuthenticated)
		return false
	}
	if password != "" {
		if verr := s.svc.CheckUserPassword(r.Context(), claims.UserID, password); verr != nil {
			if errors.Is(verr, core.ErrPasswordResetRequired) {
				unauthorized(w, ErrPasswordResetRequired)
				return false
			}
			unauthorized(w, ErrInvalidPassword)
			return false
		}
		if err := s.svc.MarkSessionAuthenticated(r.Context(), claims.UserID, claims.SessionID); err != nil {
			serverErr(w, ErrReauthFailed)
			return false
		}
		return true
	}
	s.reauthRequired(w, r, claims)
	return false
}

func (s *Service) reauthRequired(w http.ResponseWriter, r *http.Request, claims Claims) {
	freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
	sendErrData(w, http.StatusForbidden, ErrReauthRequired, map[string]any{
		"reauth_methods": s.reauthMethods(r, claims.UserID),
		"fresh_auth":     sessionFreshnessResponse(freshness),
	})
}

func (s *Service) reauthMethods(r *http.Request, userID string) []string {
	methods := []string{}
	if s.svc.HasPassword(r.Context(), userID) {
		methods = append(methods, "password")
	}
	pg := s.svc.Postgres()
	if pg == nil {
		return methods
	}
	providers, err := db.New(db.ForSchema(pg, s.svc.Schema())).UserProviderSlugsDistinct(r.Context(), strings.TrimSpace(userID))
	if err != nil {
		return methods
	}
	for _, provider := range providers {
		if _, ok := s.oidcManager().IssuerFor(provider); ok {
			methods = append(methods, provider)
		}
	}
	return methods
}

func sessionFreshnessResponse(f core.SessionFreshness) map[string]any {
	out := map[string]any{
		"reauth_required_for_sensitive_actions": f.ReauthRequiredForSensitiveOps,
		"time_until_reauth_required":            int64((f.TimeUntilReauthRequired + time.Second - time.Nanosecond) / time.Second),
	}
	if !f.LastAuthenticatedAt.IsZero() {
		out["last_authenticated_at"] = f.LastAuthenticatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func sanitizeReauthReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	return value
}

func redirectReauthResult(w http.ResponseWriter, r *http.Request, returnTo, status string) {
	target := sanitizeReauthReturnTo(returnTo)
	u, err := url.Parse(target)
	if err != nil || u == nil {
		u = &url.URL{Path: "/"}
	}
	q := u.Query()
	q.Set("reauth", status)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
