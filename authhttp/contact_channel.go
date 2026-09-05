package authhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/verify"
)

// contactChannel binds one contact channel — email or phone — to its
// validator, normalizer, sender, engine calls and wire codes. Every contact
// flow (verification, contact change, password reset, registration resend)
// has ONE route and dispatches through contactChannelFor: an identifier with
// "@" is an email, anything else is a phone number — the rule passwordless
// login already applies (#312).
type contactChannel struct {
	name           string // "email" | "phone"
	method         string // session auth-method label
	sendStage      string // delivery-failure log stage for verification sends
	resetSendStage string // delivery-failure log stage for reset sends

	validate        func(string) error
	normalize       func(string) string
	senderAvailable func() bool

	requestVerification  func(context.Context, string) error
	requestChange        func(ctx context.Context, userID, id string) error
	requestPasswordReset func(ctx context.Context, id string, ip, ua *string) error
	// resendPending re-issues the pending registration for id; found is false
	// when no pending registration exists.
	resendPending func(context.Context, string) (found bool, err error)

	confirmPendingCode func(ctx context.Context, id, code string) (string, error)
	confirmVerifyCode  func(ctx context.Context, id, code string) (string, error)
	confirmChangeCode  func(ctx context.Context, userID, id, code string, keepSessionID *string) error
	clearCodeAttempts  func(context.Context, string)
	recordFailedCode   func(context.Context, string)

	confirmPendingToken func(context.Context, string) (string, error)
	confirmVerifyToken  func(context.Context, string) (string, error)
	confirmChangeToken  func(context.Context, string) (string, error)

	getUser       func(context.Context, string) (*authcore.User, error)
	isVerified    func(*authcore.User) bool
	pendingExists func(context.Context, string) (bool, error)

	errVerifyUnavailable ErrorCode
	errResetUnavailable  ErrorCode
	errResendUnavailable ErrorCode
	errUnchanged         ErrorCode
	errInUse             ErrorCode
	errChangeFailed      ErrorCode
	errAlreadyVerified   ErrorCode
}

func (s *Service) emailChannel() contactChannel {
	return contactChannel{
		name:            "email",
		method:          "email_verification",
		sendStage:       "send_email_verification",
		resetSendStage:  "send_email_password_reset",
		validate:        embedded.ValidateEmail,
		normalize:       embedded.NormalizeEmail,
		senderAvailable: s.svc.HasEmailSender,
		requestVerification: func(ctx context.Context, id string) error {
			return s.svc.RequestEmailVerification(ctx, id, 0)
		},
		requestChange: s.svc.RequestEmailChange,
		requestPasswordReset: func(ctx context.Context, id string, ip, ua *string) error {
			return s.svc.RequestPasswordReset(ctx, id, 0, ip, ua)
		},
		resendPending: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingRegistrationByEmail(ctx, id)
			if err != nil || p == nil {
				return false, nil
			}
			_, err = s.svc.CreatePendingRegistrationWithLanguage(ctx, id, p.Username, p.PasswordHash, 0, p.PreferredLanguage)
			return true, err
		},
		confirmPendingCode:  s.svc.ConfirmPendingRegistration,
		confirmVerifyCode:   s.svc.ConfirmEmailVerification,
		confirmChangeCode:   s.svc.ConfirmEmailChange,
		clearCodeAttempts:   s.svc.ClearEmailVerifyCodeAttempts,
		recordFailedCode:    s.svc.RecordFailedEmailVerifyCode,
		confirmPendingToken: s.svc.ConfirmPendingRegistrationByToken,
		confirmVerifyToken:  s.svc.ConfirmEmailVerificationByToken,
		confirmChangeToken:  s.svc.ConfirmEmailChangeByToken,
		getUser:             s.svc.GetUserByEmail,
		isVerified:          func(u *authcore.User) bool { return u.EmailVerified },
		pendingExists: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingRegistrationByEmail(ctx, id)
			return p != nil, err
		},
		errVerifyUnavailable: ErrEmailVerificationUnavailable,
		errResetUnavailable:  ErrEmailPasswordResetUnavailable,
		errResendUnavailable: ErrEmailUnavailable,
		errUnchanged:         ErrEmailUnchanged,
		errInUse:             ErrEmailInUse,
		errChangeFailed:      ErrFailedToRequestEmailChange,
		errAlreadyVerified:   ErrEmailAlreadyVerified,
	}
}

func (s *Service) phoneChannel() contactChannel {
	return contactChannel{
		name:            "phone",
		method:          "phone_verification",
		sendStage:       "send_phone_verification",
		resetSendStage:  "send_sms_password_reset",
		validate:        embedded.ValidatePhone,
		normalize:       embedded.NormalizePhone,
		senderAvailable: s.svc.SMSAvailable,
		requestVerification: func(ctx context.Context, id string) error {
			return s.svc.RequestPhoneVerification(ctx, id, 0)
		},
		requestChange: s.svc.RequestPhoneChange,
		requestPasswordReset: func(ctx context.Context, id string, ip, ua *string) error {
			return s.svc.RequestPhonePasswordReset(ctx, id, 0, ip, ua)
		},
		resendPending: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, id)
			if err != nil || p == nil {
				return false, nil
			}
			_, err = s.svc.CreatePendingPhoneRegistrationWithLanguage(ctx, id, p.Username, p.PasswordHash, p.PreferredLanguage)
			return true, err
		},
		confirmPendingCode:  s.svc.ConfirmPendingPhoneRegistration,
		confirmVerifyCode:   s.svc.ConfirmPhoneVerificationUserID,
		confirmChangeCode:   s.svc.ConfirmPhoneChange,
		clearCodeAttempts:   s.svc.ClearPhoneVerifyCodeAttempts,
		recordFailedCode:    s.svc.RecordFailedPhoneVerifyCode,
		confirmPendingToken: s.svc.ConfirmPendingPhoneRegistrationByToken,
		confirmVerifyToken:  s.svc.ConfirmPhoneVerificationByTokenUserID,
		confirmChangeToken:  s.svc.ConfirmPhoneChangeByToken,
		getUser:             s.svc.GetUserByPhone,
		isVerified:          func(u *authcore.User) bool { return u.PhoneVerified },
		pendingExists: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, id)
			return p != nil, err
		},
		errVerifyUnavailable: ErrPhoneVerificationUnavailable,
		errResetUnavailable:  ErrSMSUnavailable,
		errResendUnavailable: ErrPhoneUnavailable,
		errUnchanged:         ErrPhoneUnchanged,
		errInUse:             ErrPhoneInUse,
		errChangeFailed:      ErrFailedToRequestPhoneChange,
		errAlreadyVerified:   ErrPhoneAlreadyVerified,
	}
}

// contactChannelFor classifies identifier and returns its channel with the
// validated, normalized value.
func (s *Service) contactChannelFor(identifier string) (contactChannel, string, error) {
	identifier = strings.TrimSpace(identifier)
	ch := s.phoneChannel()
	if strings.Contains(identifier, "@") {
		ch = s.emailChannel()
	}
	if err := ch.validate(identifier); err != nil {
		return ch, "", err
	}
	return ch, ch.normalize(identifier), nil
}

// requireContactChannel is contactChannelFor for request handlers: a missing
// identifier is invalid_request, a malformed one gets its validation code.
func (s *Service) requireContactChannel(w http.ResponseWriter, identifier string) (contactChannel, string, bool) {
	if strings.TrimSpace(identifier) == "" {
		badRequest(w, ErrInvalidRequest)
		return contactChannel{}, "", false
	}
	ch, id, err := s.contactChannelFor(identifier)
	if err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return contactChannel{}, "", false
	}
	return ch, id, true
}

// POST /verify/request — {identifier, password?}. Anonymous: send a
// verification code/link. Authenticated: start a fresh-auth-gated contact
// change to identifier.
func (s *Service) handleVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLVerifyRequest) {
		return
	}
	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ch, id, ok := s.requireContactChannel(w, req.Identifier)
	if !ok {
		return
	}
	// Per-identifier check: one address/number cannot be bombed from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLVerifyRequest, id) {
		return
	}
	if !ch.senderAvailable() {
		serverErr(w, ch.errVerifyUnavailable)
		return
	}
	if claims, ok := verify.ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		if s.rateLimited(w, r, RLContactChangeRequest) {
			return
		}
		ok, authMeta := s.requireFreshAuthOrPassword(w, r, claims, req.Password)
		if !ok {
			return
		}
		if err := ch.requestChange(r.Context(), claims.UserID, id); err != nil {
			if s.handleDeliveryError(w, r, "contact_change_request", ch.sendStage, err) {
				return
			}
			if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
				badRequest(w, code)
				return
			}
			mapContactChangeError(w, err, ch.errUnchanged, ch.errInUse, ch.errChangeFailed)
			return
		}
		if len(authMeta) == 0 {
			accepted(w)
			return
		}
		writeJSON(w, http.StatusAccepted, authMeta)
		return
	}
	if err := ch.requestVerification(r.Context(), id); err != nil {
		if s.handleDeliveryError(w, r, "verify_request", ch.sendStage, err) {
			return
		}
		if handleVerificationRequestError(w, err) {
			return
		}
		s.logInternalError(r, "verify_request", "request_"+ch.name+"_verification", "verification_request_failed", err)
		serverErr(w, ErrVerificationRequestFailed)
		return
	}
	accepted(w)
}

// POST /verify/confirm — {identifier, code} or {token, identifier?}.
func (s *Service) handleVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLVerifyConfirm) {
		return
	}
	var req struct {
		Identifier string `json:"identifier"`
		Code       string `json:"code"`
		Token      string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if token := strings.TrimSpace(req.Token); token != "" {
		s.confirmVerificationToken(w, r, token, req.Identifier)
		return
	}
	// Typed 6-digit code: only ever checked against the record issued for the
	// supplied identifier and attempt-capped per identifier (a per-IP-only
	// limit is trivially defeated by IP rotation).
	code := strings.ToUpper(strings.TrimSpace(req.Code))
	if code == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ch, id, ok := s.requireContactChannel(w, req.Identifier)
	if !ok {
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLVerifyConfirm, id) {
		return
	}
	// Pending registration, then standalone verification, then contact change.
	// A backend failure on any path is a 500 and is never counted as a guess.
	userID, err := ch.confirmPendingCode(r.Context(), id, code)
	if err == nil && userID != "" {
		ch.clearCodeAttempts(r.Context(), id)
		s.issueVerificationTokens(w, r, userID, ch.method)
		return
	}
	if s.confirmBackendFailed(w, r, "verify_confirm", "confirm_pending_registration", err) {
		return
	}
	userID, err = ch.confirmVerifyCode(r.Context(), id, code)
	if err == nil && userID != "" {
		ch.clearCodeAttempts(r.Context(), id)
		s.issueVerificationTokens(w, r, userID, ch.method)
		return
	}
	if s.confirmBackendFailed(w, r, "verify_confirm", "confirm_verification", err) {
		return
	}
	if claims, ok := verify.ClaimsFromContext(r.Context()); ok && claims.UserID != "" {
		err := ch.confirmChangeCode(r.Context(), claims.UserID, id, code, keepSession(claims))
		if err == nil {
			ch.clearCodeAttempts(r.Context(), id)
			noContent(w)
			return
		}
		if s.confirmBackendFailed(w, r, "verify_confirm", "confirm_contact_change", err) {
			return
		}
	}
	// Every path failed on the code itself: count the guess and (after the
	// cap) invalidate the code.
	ch.recordFailedCode(r.Context(), id)
	badRequest(w, ErrInvalidOrExpiredCode)
}

// confirmVerificationToken runs the link flow: pending registration, then
// standalone verification, then contact change. A link token is opaque, so
// with no identifier both channels are tried; with one, only its channel is
// tried and it drives the failure classification.
func (s *Service) confirmVerificationToken(w http.ResponseWriter, r *http.Request, token, identifier string) {
	channels := []contactChannel{s.emailChannel(), s.phoneChannel()}
	var target *contactChannel
	id := strings.TrimSpace(identifier)
	if id != "" {
		ch, normalized, err := s.contactChannelFor(id)
		if err != nil {
			badRequest(w, ErrInvalidOrExpiredToken)
			return
		}
		channels, target, id = []contactChannel{ch}, &ch, normalized
	}
	for _, ch := range channels {
		if userID, err := ch.confirmPendingToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
			s.issueVerifiedTokens(w, r, userID, ch.method)
			return
		}
		if userID, err := ch.confirmVerifyToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
			s.issueVerifiedTokens(w, r, userID, ch.method)
			return
		}
		if userID, err := ch.confirmChangeToken(r.Context(), token); err == nil && strings.TrimSpace(userID) != "" {
			noContent(w)
			return
		}
	}
	if target == nil {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	s.classifyVerifyLinkFailure(w, r.Context(), *target, id)
}

// classifyVerifyLinkFailure explains a missed link token for a known
// identifier: already verified → 409; a live account or an unknown identifier
// → 410 (the link expired); a pending registration → 400 (wrong token).
func (s *Service) classifyVerifyLinkFailure(w http.ResponseWriter, ctx context.Context, ch contactChannel, id string) {
	if u, err := ch.getUser(ctx, id); err == nil && u != nil {
		if ch.isVerified(u) {
			sendErr(w, http.StatusConflict, ch.errAlreadyVerified)
			return
		}
		sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
		return
	}
	if exists, err := ch.pendingExists(ctx, id); err == nil && exists {
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	sendErr(w, http.StatusGone, ErrVerificationLinkExpired)
}

// mapContactChangeError maps a RequestEmailChange/RequestPhoneChange failure to
// the channel's wire code. NOTE: it matches err.Error() SUBSTRINGS — fragile by
// design; typed sentinels are tracked separately (#290), not here.
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

// GET /verify/confirm and GET /password/reset/confirm hand the emailed/texted
// link to the host SPA.
func (s *Service) handleVerifyConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.VerifyPath)
}

func (s *Service) handlePasswordResetConfirmGET(w http.ResponseWriter, r *http.Request) {
	s.redirectLinkLanding(w, r, s.svc.Config().Frontend.PasswordResetPath)
}

// redirectLinkLanding hands the link token to the host SPA in the URL FRAGMENT
// (never the query: fragments are not sent to the server, do not land in
// access logs or Referer) with Cache-Control: no-store — the same shape
// browser_error.go uses for its token-bearing redirects (ak#324). Frontends
// read location.hash on VerifyPath / PasswordResetPath; an optional
// ?channel=email|phone is passed through so one landing page serves both.
func (s *Service) redirectLinkLanding(w http.ResponseWriter, r *http.Request, frontendPath string) {
	q := url.Values{}
	q.Set("status", "ready")
	if ch := r.URL.Query().Get("channel"); ch == "email" || ch == "phone" {
		q.Set("channel", ch)
	}
	if token := strings.TrimSpace(r.URL.Query().Get("token")); token != "" {
		q.Set("token", token)
	} else {
		q.Set("status", "invalid_request")
	}
	if rt := sanitizeReturnTo(r.URL.Query().Get("return_to")); rt != "/" {
		q.Set("return_to", rt)
	}
	if strings.TrimSpace(frontendPath) == "" {
		frontendPath = "/"
	}
	target := strings.TrimRight(strings.TrimSpace(s.svc.Config().Frontend.BaseURL), "/") + frontendPath + "#" + q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

// POST /password/reset/request — {identifier}; always 202 for a well-formed
// identifier (anti-enumeration: existence is never revealed).
func (s *Service) handlePasswordResetRequestPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetRequest) {
		return
	}
	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Identifier) == "" {
		accepted(w)
		return
	}
	ch, id, ok := s.requireContactChannel(w, req.Identifier)
	if !ok {
		return
	}
	// Per-identifier check: one address/number cannot be bombed from many IPs.
	if s.rateLimitedByIdentifier(w, r, RLPasswordResetRequest, id) {
		return
	}
	if !ch.senderAvailable() {
		serverErr(w, ch.errResetUnavailable)
		return
	}
	ua, ip := r.UserAgent(), remoteIP(r)
	if err := ch.requestPasswordReset(r.Context(), id, &ip, &ua); err != nil {
		if s.handleDeliveryError(w, r, "password_reset_request", ch.resetSendStage, err) {
			return
		}
		s.logInternalError(r, "password_reset_request", "request_password_reset", "password_reset_request_failed", err)
		serverErr(w, ErrPasswordResetRequestFailed)
		return
	}
	accepted(w)
}

// POST /password/reset/confirm — {token, new_password}.
func (s *Service) handlePasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLPasswordResetConfirm) {
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := embedded.ValidatePassword(req.NewPassword); err != nil {
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
		return
	}
	if _, err := s.svc.ConfirmPasswordReset(r.Context(), strings.TrimSpace(req.Token), req.NewPassword); err != nil {
		if code := ErrorCode(embedded.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		if s.confirmBackendFailed(w, r, "password_reset_confirm", "confirm_password_reset", err) {
			return
		}
		badRequest(w, ErrInvalidOrExpiredToken)
		return
	}
	noContent(w)
}

// POST /register/resend — {identifier}: re-issue a pending registration's code.
func (s *Service) handleRegisterResendPOST(w http.ResponseWriter, r *http.Request) {
	if s.publicRegistrationDisabled() {
		registrationDisabled(w)
		return
	}
	if !s.svc.RegistrationVerificationEnabled() {
		accepted(w)
		return
	}
	if s.rateLimited(w, r, RLRegisterResend) {
		return
	}
	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ch, id, ok := s.requireContactChannel(w, req.Identifier)
	if !ok {
		return
	}
	if !ch.senderAvailable() {
		serverErr(w, ch.errResendUnavailable)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLRegisterResend, id) {
		return
	}
	found, err := ch.resendPending(r.Context(), id)
	if !found {
		notFound(w, ErrPendingRegistrationNotFound)
		return
	}
	if err != nil {
		if s.handleDeliveryError(w, r, "register_resend", ch.sendStage, err) {
			return
		}
		s.logInternalError(r, "register_resend", "create_pending_registration", "resend_failed", err)
		serverErr(w, ErrResendFailed)
		return
	}
	accepted(w)
}
