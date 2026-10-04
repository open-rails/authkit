package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
)

// authExtras are the parts of an AuthResult a login outcome does not carry.
type authExtras struct {
	deviceKey *iam.DeviceKey // a device-key sign-in's key
	freshAuth *FreshAuth     // a re-authentication's step-up state
}

// authResult is the one builder of AuthResult: a login outcome and the
// route's extras. A session's refresh token goes through deliverRefreshToken,
// so a cookie mount never puts it in the body. A rejected login is its error.
func (s *Service) authResult(w http.ResponseWriter, r *http.Request, out authflow.LoginOutcome, extra authExtras) (AuthResult, error) {
	res := AuthResult{ReturnTo: nullableString(out.ReturnTo)}
	switch out.Kind {
	case authflow.LoginSessionIssued:
		user, err := s.svc.User(r.Context(), iam.UserByID(out.UserID))
		if err != nil {
			return AuthResult{}, errmodel.Internal("user_lookup_failed", err)
		}
		tokens := s.deliverRefreshToken(w, r, out.Session.TokenSet())
		res.Status, res.TokenSet, res.User, res.Created = AuthComplete, &tokens, &user, out.Created
		res.DeviceKey, res.FreshAuth = extra.deviceKey, extra.freshAuth
	case authflow.LoginTwoFactorRequired:
		res.Status = AuthSecondFactorRequired
		res.SecondFactor = secondFactorStep(out.UserID, out.Challenge)
	case authflow.LoginTwoFAEnrollmentRequired:
		allowed := out.AllowedMethods
		if allowed == nil {
			allowed = []iam.TwoFactorMethod{}
		}
		res.Status = AuthEnrollmentRequired
		res.Enrollment = &EnrollmentStep{TokenSet: *out.Enrollment, AllowedMethods: allowed}
	case authflow.LoginVerificationRequired:
		res.Status = AuthVerificationRequired
		res.Verification = &VerificationStep{Identifier: out.Verification.Identifier, Channel: out.Verification.Channel, PasswordProof: nullableString(out.Verification.PasswordProof)}
	case authflow.LoginRecoveryRequired:
		res.Status = AuthAccountRecoveryRequired
		res.Recovery = out.Recovery
	case authflow.LoginDeviceVerificationRequired:
		res.Status = AuthDeviceVerificationRequired
		res.DeviceVerification = deviceVerificationStep(out.UserID, out.Device)
	default:
		return AuthResult{}, errmodel.E(loginRejectionCode(out.Reason))
	}
	return res, nil
}

// writeAuthResult answers a sign-in: 200 and its AuthResult, or its error.
func (s *Service) writeAuthResult(w http.ResponseWriter, r *http.Request, out authflow.LoginOutcome, extra authExtras) {
	res, err := s.authResult(w, r, out, extra)
	if err != nil {
		writeError(w, err)
		return
	}
	writeAuthResult(w, res)
}

// writeAuthResult writes res uncached: it carries tokens.
func writeAuthResult(w http.ResponseWriter, res AuthResult) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, res)
}

// freshAuthResult is a re-authenticated session's AuthResult: a fresh access
// token whose assurance claims match the session, and its step-up state.
func (s *Service) freshAuthResult(w http.ResponseWriter, r *http.Request, userID, sessionID string) (AuthResult, error) {
	token, exp, err := s.svc.MintSessionAccessToken(r.Context(), userID, sessionID)
	if err != nil {
		return AuthResult{}, errmodel.Internal("token_issue_failed", err)
	}
	freshness, err := s.svc.SessionFreshness(r.Context(), userID, sessionID, time.Now())
	if err != nil {
		return AuthResult{}, errmodel.Internal("token_issue_failed", err)
	}
	fresh := freshAuth(freshness)
	out := authflow.LoginOutcome{Kind: authflow.LoginSessionIssued, UserID: userID, Session: &authflow.IssuedSession{SessionID: sessionID, AccessToken: token, AccessExpiresAt: exp}}
	return s.authResult(w, r, out, authExtras{freshAuth: &fresh})
}

// secondFactorStep is a challenge on the wire: the factor its code went to,
// with that destination masked, and the factors to switch to.
func secondFactorStep(userID string, ch *authflow.TwoFactorChallenge) *SecondFactorStep {
	factor := authflow.WireFactor(ch.Factor)
	if factor.Method == "" {
		factor.Method = ch.Method // backup codes only: no factor was sent a code
	}
	if ch.Destination != "" && ch.Method != "totp" {
		masked := contact.MaskDestination(ch.Destination)
		factor.Destination = &masked
	}
	return &SecondFactorStep{UserID: userID, Challenge: ch.Challenge, Factor: factor, Factors: authflow.WireFactors(ch.Factors)}
}

func loginRejectionCode(reason error) errmodel.Code {
	switch {
	case errors.Is(reason, errmodel.ErrUserBanned):
		return errmodel.CodeUserBanned
	case errors.Is(reason, errmodel.ErrPasswordResetRequired):
		return errmodel.CodePasswordResetRequired
	default:
		return errmodel.CodeInvalidCredentials
	}
}
