package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
)

// writeLoginContinuation is the one JSON presentation of first-factor outcomes.
// It returns false only for an issued session, whose surrounding envelope may
// carry registration/passwordless metadata.
func (s *Service) writeLoginContinuation(w http.ResponseWriter, r *http.Request, out authflow.LoginOutcome, extra map[string]any) bool {
	switch out.Kind {
	case authflow.LoginSessionIssued:
		return false
	case authflow.LoginRecoveryRequired:
		w.Header().Set("Cache-Control", "no-store")
		sendErrData(w, http.StatusConflict, iam.CodeAccountRecoveryRequired, map[string]any{"recovery": out.Recovery})
	case authflow.LoginTwoFactorRequired:
		metadata := loginChallengeMetadata(out.UserID, out.Challenge)
		for key, value := range extra {
			metadata[key] = value
		}
		if out.ReturnTo != "" {
			metadata["return_to"] = out.ReturnTo
		}
		sendErrData(w, http.StatusForbidden, iam.CodeTwoFARequired, metadata)
	case authflow.LoginTwoFAEnrollmentRequired:
		sendErrData(w, http.StatusForbidden, iam.CodeTwoFAEnrollmentRequired, map[string]any{"user_id": out.UserID, "requires_2fa_enrollment": true, "allowed_methods": out.AllowedMethods, "token_set": out.Enrollment, "return_to": out.ReturnTo})
	case authflow.LoginVerificationRequired:
		writeVerificationRequired(w, out.Verification.Identifier, out.Verification.Channel)
	default:
		unauthorized(w, loginRejectionCode(out.Reason))
	}
	return true
}

func loginChallengeMetadata(userID string, ch *authflow.TwoFactorChallenge) map[string]any {
	return map[string]any{"user_id": userID, "method": ch.Method, "verification_id": contact.MaskDestination(ch.Destination), "challenge": ch.Challenge, "default_factor": TwoFactorFactorResponse{ID: ch.Factor.ID, Method: ch.Factor.Method, IsDefault: ch.Factor.IsDefault, PhoneNumber: ch.Factor.PhoneNumber}, "available_factors": twoFactorFactorResponses(ch.Factors)}
}
