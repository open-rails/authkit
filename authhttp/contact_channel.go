package authhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/verify"
)

// contactChannel binds one contact channel — email or phone — to its
// validator, normalizer, sender, engine calls and wire codes. Every contact
// flow (verification, contact change, password reset, registration resend)
// has ONE route and dispatches through contactChannelFor: an identifier with
// "@" is an email, anything else is a phone number — the rule passwordless
// login already applies (#312).
type contactChannel struct {
	name   string // "email" | "phone"
	method string // session auth-method label

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

	getUser       func(context.Context, string) (*embedded.User, error)
	isVerified    func(*embedded.User) bool
	pendingExists func(context.Context, string) (bool, error)

	errVerifyUnavailable authkit.Code
	errResetUnavailable  authkit.Code
	errResendUnavailable authkit.Code
	errAlreadyVerified   authkit.Code
}

func (s *Service) emailChannel() contactChannel {
	return contactChannel{
		name:            "email",
		method:          "email_verification",
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
		isVerified:          func(u *embedded.User) bool { return u.EmailVerified },
		pendingExists: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingRegistrationByEmail(ctx, id)
			return p != nil, err
		},
		errVerifyUnavailable: authkit.CodeEmailVerificationUnavailable,
		errResetUnavailable:  authkit.CodeEmailPasswordResetUnavailable,
		errResendUnavailable: authkit.CodeEmailUnavailable,
		errAlreadyVerified:   authkit.CodeEmailAlreadyVerified,
	}
}

func (s *Service) phoneChannel() contactChannel {
	return contactChannel{
		name:            "phone",
		method:          "phone_verification",
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
		isVerified:          func(u *embedded.User) bool { return u.PhoneVerified },
		pendingExists: func(ctx context.Context, id string) (bool, error) {
			p, err := s.svc.GetPendingPhoneRegistrationByPhone(ctx, id)
			return p != nil, err
		},
		errVerifyUnavailable: authkit.CodePhoneVerificationUnavailable,
		errResetUnavailable:  authkit.CodeSMSSenderUnavailable,
		errResendUnavailable: authkit.CodePhoneUnavailable,
		errAlreadyVerified:   authkit.CodePhoneAlreadyVerified,
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
		badRequest(w, authkit.CodeInvalidRequest)
		return contactChannel{}, "", false
	}
	ch, id, err := s.contactChannelFor(identifier)
	if err != nil {
		writeError(w, err)
		return contactChannel{}, "", false
	}
	return ch, id, true
}

// POST /verify/request — {identifier, password?}. Anonymous: send a
// verification code/link. Authenticated: start a fresh-auth-gated contact
// change to identifier.
func (s *Service) handleVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
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
			writeError(w, err)
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
		writeError(w, err)
		return
	}
	accepted(w)
}

// POST /verify/confirm — {identifier, code} or {token, identifier?}.
func (s *Service) handleVerifyConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		Code       string `json:"code"`
		Token      string `json:"token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
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
		badRequest(w, authkit.CodeInvalidRequest)
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
	badRequest(w, authkit.CodeInvalidOrExpiredCode)
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
			badRequest(w, authkit.CodeInvalidOrExpiredToken)
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
		badRequest(w, authkit.CodeInvalidOrExpiredToken)
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
		sendErr(w, http.StatusGone, authkit.CodeVerificationLinkExpired)
		return
	}
	if exists, err := ch.pendingExists(ctx, id); err == nil && exists {
		badRequest(w, authkit.CodeInvalidOrExpiredToken)
		return
	}
	sendErr(w, http.StatusGone, authkit.CodeVerificationLinkExpired)
}

func (s *Service) issueVerifiedTokens(w http.ResponseWriter, r *http.Request, userID, method string) {
	if err := s.issueTokensForUser(w, r, userID, method); err != nil {
		if errors.Is(err, authkit.ErrUserBanned) {
			unauthorized(w, authkit.CodeUserBanned)
			return
		}
		serverErr(w, authkit.CodeTokenIssueFailed)
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
		writeError(w, err)
		return
	}
	accepted(w)
}

// POST /password/reset/confirm — {token, new_password}.
func (s *Service) handlePasswordResetConfirmPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" || req.NewPassword == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err := embedded.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.svc.ConfirmPasswordReset(r.Context(), strings.TrimSpace(req.Token), req.NewPassword); err != nil {
		if code := embedded.ValidationErrorCode(err); code != "" {
			badRequest(w, code)
			return
		}
		if s.confirmBackendFailed(w, r, "password_reset_confirm", "confirm_password_reset", err) {
			return
		}
		badRequest(w, authkit.CodeInvalidOrExpiredToken)
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
	var req struct {
		Identifier string `json:"identifier"`
	}
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
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
		notFound(w, authkit.CodePendingRegistrationNotFound)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	accepted(w)
}
