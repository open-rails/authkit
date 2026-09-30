package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

func (s *Service) handleMe2FAGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}

	settings, err := s.svc.Get2FASettings(r.Context(), claims.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, TwoFactorStatus{Factors: []TwoFactorFactor{}, AllowedMethods: s.svc.TwoFactorAllowedMethods()})
		return
	}

	writeJSON(w, http.StatusOK, TwoFactorStatus{
		Enabled:              settings.Enabled,
		Factors:              twoFactorFactorResponses(settings.Factors),
		AllowedMethods:       s.svc.TwoFactorAllowedMethods(),
		BackupCodesRemaining: len(settings.BackupCodes),
	})
}

// handleUser2FAPOST: decode, the freshness gate, rate limits, one engine
// call, one switch. The enrollment policy (factor slot, method availability,
// phone/code validation, SMS setup code, TOTP hand-out, enable) is
// authkit.EnrollTwoFactor (ak#318).
func (s *Service) handleUser2FAPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	scope, err := s.svc.BeginTwoFactorEnrollment(r.Context(), claims.UserID, claims.TwoFAEnrollment, claims.SessionID)
	if err != nil {
		writeError(w, err)
		return
	}
	if !claims.TwoFAEnrollment {
		if !s.requireProvenContact(w, r, claims.UserID) {
			return
		}
		// A token minted before enrollment must not hide the account's current MFA requirement.
		claims.MFAEnrolled = scope.HasFactors
		if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
			return
		}
	}

	var req TwoFactorEnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if claims.TwoFAEnrollment && strings.TrimSpace(req.FactorID) != "" {
		fail(w, errmodel.CodeForbidden)
		return
	}
	method := strings.ToLower(strings.TrimSpace(req.Method))
	phone := ""
	if req.PhoneNumber != nil {
		phone = strings.TrimSpace(*req.PhoneNumber)
	}
	// Anti-spam velocity on the code-sending starts (authkit owns velocity).
	starting := strings.TrimSpace(req.Code) == ""
	switch {
	case method == "sms" && starting && phone != "" && strings.HasPrefix(phone, "+"):
		if s.rateLimited(w, r, RL2FAStartPhone) || s.rateLimitedByIdentifier(w, r, RL2FAStartPhone, contact.NormalizePhone(phone)) {
			return
		}
	case method == "totp" && starting:
		if s.rateLimited(w, r, RL2FAStartTOTP) {
			return
		}
	case method == "email" && starting:
		if s.rateLimited(w, r, RL2FAStartEmail) || s.rateLimitedByIdentifier(w, r, RL2FAStartEmail, claims.UserID) {
			return
		}
	}

	challenge := ""
	if claims.TwoFAEnrollment {
		challenge = claims.JTI
	}
	out, err := s.svc.EnrollTwoFactor(r.Context(), authflow.TwoFactorEnrollInput{
		LoginChallenge: challenge, SessionID: claims.SessionID, UserAgent: r.UserAgent(), IP: s.requestIP(r),
		UserID: claims.UserID, Mode: scope.Mode, Method: method, Code: req.Code,
		PhoneNumber: phone, MakeDefault: req.Default, FactorID: req.FactorID,
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenUnverifiable) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
			fail(w, errmodel.CodeInvalidChallenge)
		} else {
			writeError(w, err)
		}
		return
	}
	switch out.Kind {
	case authflow.TwoFactorEnrollDefaultSet:
		noContent(w)
	case authflow.TwoFactorEnrollCodeSent:
		accepted(w)
	case authflow.TwoFactorEnrollTOTPStarted:
		writeJSON(w, http.StatusOK, TwoFactorEnrollResult{Method: "totp", Secret: &out.Secret, OTPAuthURI: &out.OTPAuthURI})
	default:
		resp := TwoFactorEnrollResult{Enabled: true, Method: out.Method, BackupCodes: out.BackupCodes}
		if out.Login != nil {
			if s.writeLoginContinuation(w, r, *out.Login, enabledMeta(out)) {
				return
			}
			tokens := s.deliverRefreshToken(w, r, out.Login.Session.TokenSet())
			resp.TokenSet = &tokens
			writeJSON(w, http.StatusOK, resp)
			return
		}
		// The confirmed code verified this session: hand back a token whose
		// assurance claims match what its next refresh will carry (#389).
		if out.SessionVerified {
			freshness, _ := s.svc.SessionFreshness(r.Context(), claims.UserID, claims.SessionID, time.Now())
			fresh, err := s.freshAccessTokenResponse(r, claims.UserID, claims.SessionID, freshness)
			if err != nil {
				serverErr(w, "token_issue_failed", err)
				return
			}
			resp.TokenSet, resp.FreshAuth = &fresh.TokenSet, &fresh.FreshAuth
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (s *Service) handleMe2FADELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	var q TwoFactorFactorQuery
	if !readQuery(w, r, &q) {
		return
	}
	factorID := q.FactorID
	var removed []authflow.RemovedMFARoleAssignment
	var err error
	if factorID == "" {
		removed, err = s.svc.Disable2FAWithRemovedRoles(r.Context(), claims.UserID)
	} else {
		removed, err = s.svc.Disable2FAFactorWithRemovedRoles(r.Context(), claims.UserID, factorID)
	}
	if err != nil {
		writeError(w, err)
		return
	}

	out := RemovedRoles{RemovedRoles: make([]RemovedRole, 0, len(removed))}
	for _, r := range removed {
		out.RemovedRoles = append(out.RemovedRoles, RemovedRole{GroupID: r.PermissionGroupID, Persona: r.Persona, Role: r.Role, RemovedAt: r.RemovedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// enabledMeta carries the enabled factor, and the first factor's backup
// codes, on the sign-in continuation the enrollment leads to.
func enabledMeta(out authflow.TwoFactorEnrollOutcome) map[string]any {
	meta := map[string]any{"enabled": true, "method": out.Method}
	if len(out.BackupCodes) > 0 {
		meta["backup_codes"] = out.BackupCodes
	}
	return meta
}

func (s *Service) handleMe2FABackupCodesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, "regenerate_codes_failed", err)
		return
	}
	writeJSON(w, http.StatusOK, BackupCodes{BackupCodes: backupCodes})
}

func twoFactorFactorResponses(factors []authflow.TwoFactorFactor) []TwoFactorFactor {
	out := make([]TwoFactorFactor, 0, len(factors))
	for _, factor := range factors {
		out = append(out, twoFactorFactorResponse(factor))
	}
	return out
}

func twoFactorFactorResponse(factor authflow.TwoFactorFactor) TwoFactorFactor {
	out := TwoFactorFactor{ID: factor.ID, Method: factor.Method, IsDefault: factor.IsDefault}
	destination := factor.Email
	if factor.Method == "sms" {
		destination = factor.PhoneNumber
	}
	if destination != nil && factor.Method != "totp" {
		masked := contact.MaskDestination(*destination)
		out.Destination = &masked
	}
	return out
}
