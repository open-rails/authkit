package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/verify"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

type twoFactorStatusResponse struct {
	Enabled              bool                      `json:"enabled"`
	Method               string                    `json:"method"`
	PhoneNumber          *string                   `json:"phone_number,omitempty"`
	DefaultFactor        *twoFactorFactorResponse  `json:"default_factor,omitempty"`
	Factors              []twoFactorFactorResponse `json:"factors,omitempty"`
	AvailableFactors     []twoFactorFactorResponse `json:"available_factors,omitempty"`
	AllowedMethods       []string                  `json:"allowed_methods,omitempty"`
	BackupCodesRemaining int                       `json:"backup_codes_remaining,omitempty"`
}

type twoFactorFactorResponse struct {
	ID          string  `json:"id,omitempty"`
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default,omitempty"`
	PhoneNumber *string `json:"phone_number,omitempty"`
}

func (s *Service) handleUser2FAStatusGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	settings, err := s.svc.Get2FASettings(r.Context(), claims.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, twoFactorStatusResponse{Enabled: false, Method: "email", AllowedMethods: s.svc.TwoFactorAllowedMethods()})
		return
	}

	factors := twoFactorFactorResponses(settings.Factors)
	writeJSON(w, http.StatusOK, twoFactorStatusResponse{
		Enabled:              settings.Enabled,
		Method:               settings.Method,
		PhoneNumber:          settings.PhoneNumber,
		DefaultFactor:        defaultTwoFactorFactorResponse(factors),
		Factors:              factors,
		AvailableFactors:     factors,
		AllowedMethods:       s.svc.TwoFactorAllowedMethods(),
		BackupCodesRemaining: len(settings.BackupCodes),
	})
}

// handleUser2FAPOST: decode, the freshness gate, rate limits, one engine
// call, one switch. The enrollment policy (factor slot, method availability,
// phone/code validation, SMS setup code, TOTP hand-out, enable) is
// embedded.EnrollTwoFactor (ak#318).
func (s *Service) handleUser2FAPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	scope, err := s.svc.BeginTwoFactorEnrollment(r.Context(), claims.UserID, claims.TwoFAEnrollment, claims.SessionID)
	if err != nil {
		if errors.Is(err, authkit.ErrTwoFAFactorExists) {
			sendErr(w, http.StatusConflict, ErrTwoFAFactorExists)
			return
		}
		serverErr(w, ErrEnableTwoFAFailed)
		return
	}
	if !claims.TwoFAEnrollment {
		// A token minted before enrollment must not hide the account's current MFA requirement.
		claims.MFAEnrolled = scope.HasFactors
		if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
			return
		}
	}

	var req struct {
		Method      string  `json:"method"`
		Code        string  `json:"code,omitempty"`
		Phone       string  `json:"phone,omitempty"`
		PhoneNumber *string `json:"phone_number"`
		Default     bool    `json:"default,omitempty"`
		FactorID    string  `json:"factor_id,omitempty"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if claims.TwoFAEnrollment && strings.TrimSpace(req.FactorID) != "" {
		forbidden(w, ErrForbidden)
		return
	}
	method := strings.ToLower(strings.TrimSpace(req.Method))
	phone := strings.TrimSpace(req.Phone)
	if req.PhoneNumber != nil {
		phone = strings.TrimSpace(*req.PhoneNumber)
	}
	// Anti-spam velocity on the code-sending starts (authkit owns velocity).
	starting := strings.TrimSpace(req.Code) == ""
	switch {
	case method == "sms" && starting && phone != "" && strings.HasPrefix(phone, "+"):
		if s.rateLimited(w, r, RL2FAStartPhone) || s.rateLimitedByIdentifier(w, r, RL2FAStartPhone, embedded.NormalizePhone(phone)) {
			return
		}
	case method == "totp" && starting:
		if s.rateLimited(w, r, RL2FAStartTOTP) {
			return
		}
	}

	out, err := s.svc.EnrollTwoFactor(r.Context(), embedded.TwoFactorEnrollInput{
		UserID: claims.UserID, Mode: scope.Mode, Method: method, Code: req.Code,
		PhoneNumber: phone, MakeDefault: req.Default, FactorID: req.FactorID,
	})
	if err != nil {
		s.writeTwoFactorEnrollError(w, r, err)
		return
	}
	switch out.Kind {
	case embedded.TwoFactorEnrollDefaultSet:
		noContent(w)
	case embedded.TwoFactorEnrollCodeSent:
		accepted(w)
	case embedded.TwoFactorEnrollTOTPStarted:
		writeJSON(w, http.StatusOK, map[string]any{
			"method":      "totp",
			"secret":      out.Secret,
			"otpauth_uri": out.OTPAuthURI,
		})
	default:
		resp := map[string]any{"enabled": true, "method": out.Method}
		if len(out.BackupCodes) > 0 {
			resp["backup_codes"] = out.BackupCodes
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (s *Service) writeTwoFactorEnrollError(w http.ResponseWriter, r *http.Request, err error) {
	if s.handleDeliveryError(w, r, "user_2fa_start_phone", flowStage(err), err) {
		return
	}
	switch {
	case errors.Is(err, authkit.ErrTwoFAFactorExists):
		sendErr(w, http.StatusConflict, ErrTwoFAFactorExists)
	case errors.Is(err, authkit.ErrInvalidTwoFAMethod):
		badRequest(w, ErrInvalidMethod)
	case errors.Is(err, authkit.ErrPhoneNumberRequired):
		badRequest(w, ErrPhoneAndCodeRequired)
	case errors.Is(err, authkit.ErrPhoneNumberMustBeE164):
		badRequest(w, ErrPhoneNumberMustBeE164)
	case errors.Is(err, authkit.ErrInvalidCode):
		badRequest(w, ErrInvalidCode)
	case errors.Is(err, authkit.ErrPhoneTwoFAUnavailable):
		serverErr(w, ErrPhoneTwoFAUnavailable)
	case errors.Is(err, authkit.ErrTwoFASetupCodeSendFailed):
		serverErr(w, ErrSendCodeFailed)
	default:
		serverErr(w, ErrEnableTwoFAFailed)
	}
}

func (s *Service) handleUser2FADELETE(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	factorID := strings.TrimSpace(r.URL.Query().Get("factor_id"))
	var body struct {
		FactorID string `json:"factor_id"`
	}
	_ = decodeJSON(r, &body)
	if factorID == "" {
		factorID = strings.TrimSpace(body.FactorID)
	}
	var removed []embedded.RemovedMFARoleAssignment
	var err error
	if factorID == "" {
		removed, err = s.svc.Disable2FAWithRemovedRoles(r.Context(), claims.UserID)
	} else {
		removed, err = s.svc.Disable2FAFactorWithRemovedRoles(r.Context(), claims.UserID, factorID)
	}
	if err != nil {
		if errors.Is(err, authkit.ErrCannotRemoveLastAdminRole) {
			sendErr(w, http.StatusConflict, ErrCannotRemoveLastOwner)
			return
		}
		serverErr(w, ErrDisableTwoFAFailed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"removed_roles": removedMFARolesResponse(removed)})
}

func removedMFARolesResponse(removed []embedded.RemovedMFARoleAssignment) []map[string]any {
	out := make([]map[string]any, 0, len(removed))
	for _, r := range removed {
		out = append(out, map[string]any{
			"permission_group_id": r.PermissionGroupID,
			"persona":             r.Persona,
			"instance_slug":       r.InstanceSlug,
			"role":                r.Role,
			"removed_at":          r.RemovedAt.UTC().Format(time.RFC3339),
		})
	}
	return out
}

func (s *Service) handleUser2FABackupCodesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	if ok, _ := s.requireFreshAuthOrPassword(w, r, claims, ""); !ok {
		return
	}

	backupCodes, err := s.svc.RegenerateBackupCodes(r.Context(), claims.UserID)
	if err != nil {
		serverErr(w, ErrRegenerateCodesFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": backupCodes})
}

func twoFactorFactorResponses(factors []embedded.TwoFactorFactor) []twoFactorFactorResponse {
	out := make([]twoFactorFactorResponse, 0, len(factors))
	for _, factor := range factors {
		out = append(out, twoFactorFactorResponse{
			ID:          factor.ID,
			Method:      factor.Method,
			IsDefault:   factor.IsDefault,
			PhoneNumber: factor.PhoneNumber,
		})
	}
	return out
}

func defaultTwoFactorFactorResponse(factors []twoFactorFactorResponse) *twoFactorFactorResponse {
	for _, factor := range factors {
		if factor.IsDefault {
			f := factor
			return &f
		}
	}
	if len(factors) == 0 {
		return nil
	}
	return &factors[0]
}
