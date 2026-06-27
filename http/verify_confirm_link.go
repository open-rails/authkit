package authhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
)

// verifyChannel parameterizes the email/phone verify-confirm-by-link twins (#179).
// Both channels run identical control flow — three confirm-by-token attempts then a
// structured failure classification — differing only in these hooks and error codes.
type verifyChannel struct {
	method             string // session auth-method label ("email_verification"/"phone_verification")
	changedMessage     string // success message for a contact-change confirm
	confirmPending     func(context.Context, string) (string, error)
	confirmVerify      func(context.Context, string) (string, error)
	confirmChange      func(context.Context, string) (string, error)
	validate           func(string) error
	normalize          func(string) string
	getUser            func(context.Context, string) (*authcore.User, error)
	isVerified         func(*authcore.User) bool
	pendingExists      func(context.Context, string) (bool, error)
	errAlreadyVerified ErrorCode
}

func (s *Service) emailVerifyChannel() verifyChannel {
	return verifyChannel{
		method:         "email_verification",
		changedMessage: "Email changed successfully",
		confirmPending: s.svc.ConfirmPendingRegistrationByToken,
		confirmVerify:  s.svc.ConfirmEmailVerificationByToken,
		confirmChange:  s.svc.ConfirmEmailChangeByToken,
		validate:       embedded.ValidateEmail,
		normalize:      embedded.NormalizeEmail,
		getUser:        s.svc.GetUserByEmail,
		isVerified:     func(u *authcore.User) bool { return u.EmailVerified },
		pendingExists: func(ctx context.Context, t string) (bool, error) {
			p, err := s.svc.GetPendingRegistrationByEmail(ctx, t)
			return p != nil, err
		},
		errAlreadyVerified: ErrEmailAlreadyVerified,
	}
}

func (s *Service) phoneVerifyChannel() verifyChannel {
	return verifyChannel{
		method:         "phone_verification",
		changedMessage: "Phone number changed successfully",
		confirmPending: s.svc.ConfirmPendingPhoneRegistrationByToken,
		confirmVerify:  s.svc.ConfirmPhoneVerificationByTokenUserID,
		confirmChange:  s.svc.ConfirmPhoneChangeByToken,
		validate:       embedded.ValidatePhone,
		normalize:      embedded.NormalizePhone,
		getUser:        s.svc.GetUserByPhone,
		isVerified:     func(u *authcore.User) bool { return u.PhoneVerified },
		pendingExists: func(ctx context.Context, t string) (bool, error) {
			p, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, t)
			return p != nil, err
		},
		errAlreadyVerified: ErrPhoneAlreadyVerified,
	}
}

// confirmVerificationToken runs the shared verify-confirm-by-link flow: try
// pending-registration, then standalone verification, then contact-change; on all
// misses, classify the failure. A banned user gets 401 on BOTH channels (#179 fixed
// the phone path, which previously surfaced a generic 500).
func (s *Service) confirmVerificationToken(w http.ResponseWriter, r *http.Request, ch verifyChannel, token, identifier, contact string) {
	if userID, err := ch.confirmPending(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		s.issueVerifiedTokens(w, r, userID, ch.method)
		return
	}
	if userID, err := ch.confirmVerify(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		s.issueVerifiedTokens(w, r, userID, ch.method)
		return
	}
	if userID, err := ch.confirmChange(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": ch.changedMessage})
		return
	}
	s.handleVerifyLinkFailure(w, r.Context(), ch, identifier, contact)
}

// mapContactChangeError maps a RequestEmailChange/RequestPhoneChange failure to the
// channel's wire code, shared by the email/phone verify-request handlers (#179) so the
// matched set stays identical across channels. NOTE: it matches err.Error() SUBSTRINGS
// — fragile by design; replacing it with typed sentinels is tracked separately (plans
// 008/009/011), not here.
func mapContactChangeError(w http.ResponseWriter, err error, unchanged, inUse, failed ErrorCode) {
	switch msg := err.Error(); {
	case strings.Contains(msg, "same as current"):
		badRequest(w, unchanged)
	case strings.Contains(msg, "already in use"):
		badRequest(w, inUse)
	default:
		badRequest(w, failed)
	}
}

func (s *Service) issueVerifiedTokens(w http.ResponseWriter, r *http.Request, userID, method string) {
	if err := s.issueTokensForUser(w, r, userID, method); err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, ErrUserBanned)
			return
		}
		serverErr(w, ErrTokenIssueFailed)
	}
}

func (s *Service) handleVerifyLinkFailure(w http.ResponseWriter, ctx context.Context, ch verifyChannel, identifier, contact string) {
	target := strings.TrimSpace(identifier)
	if target == "" {
		target = strings.TrimSpace(contact)
	}
	if target == "" {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	if err := ch.validate(target); err != nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	target = ch.normalize(target)

	if u, err := ch.getUser(ctx, target); err == nil && u != nil {
		if ch.isVerified(u) {
			sendErr(w, http.StatusConflict, ch.errAlreadyVerified)
			return
		}
		sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
		return
	}
	if exists, err := ch.pendingExists(ctx, target); err == nil && exists {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
}
