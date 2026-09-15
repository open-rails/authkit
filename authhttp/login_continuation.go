package authhttp

import (
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// writeLoginContinuation is the one JSON presentation of first-factor outcomes.
// It returns false only for an issued session, whose surrounding envelope may
// carry registration/passwordless metadata.
func (s *Service) writeLoginContinuation(w http.ResponseWriter, r *http.Request, out embedded.LoginOutcome, extra map[string]any) bool {
	switch out.Kind {
	case embedded.LoginSessionIssued:
		return false
	case embedded.LoginTwoFactorRequired:
		metadata := loginChallengeMetadata(out.UserID, out.Challenge)
		for key, value := range extra {
			metadata[key] = value
		}
		if out.ReturnTo != "" {
			metadata["return_to"] = out.ReturnTo
		}
		sendErrData(w, http.StatusForbidden, authkit.CodeTwoFARequired, metadata)
	case embedded.LoginTwoFAEnrollmentRequired:
		sendErrData(w, http.StatusForbidden, authkit.CodeTwoFAEnrollmentRequired, map[string]any{"user_id": out.UserID, "requires_2fa_enrollment": true, "allowed_methods": out.AllowedMethods, "token_set": out.Enrollment, "return_to": out.ReturnTo})
	case embedded.LoginVerificationRequired:
		writeVerificationRequired(w, out.Verification.Identifier, out.Verification.Channel)
	default:
		unauthorized(w, loginRejectionCode(out.Reason))
	}
	return true
}

func loginChallengeMetadata(userID string, ch *embedded.TwoFactorChallenge) map[string]any {
	return map[string]any{"user_id": userID, "method": ch.Method, "verification_id": embedded.MaskDestination(ch.Destination), "challenge": ch.Challenge, "default_factor": twoFactorFactorResponse{ID: ch.Factor.ID, Method: ch.Factor.Method, IsDefault: ch.Factor.IsDefault, PhoneNumber: ch.Factor.PhoneNumber}, "available_factors": twoFactorFactorResponses(ch.Factors)}
}
