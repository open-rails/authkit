package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// contactChannel binds one contact channel — email or phone — to its
// validator, normalizer, sender, engine calls and wire codes. Every contact
// flow (verification, contact change, password reset) has ONE route and
// dispatches through contactChannelFor: an identifier with
// "@" is an email, anything else is a phone number — the rule passwordless
// login already applies (#312).
type contactChannel struct {
	validate        func(string) error
	normalize       func(string) string
	senderAvailable func() bool

	requestVerification  func(context.Context, string) error
	requestChange        func(ctx context.Context, userID, id string) error
	requestPasswordReset func(ctx context.Context, id string, ip, ua *string) error

	errUnavailable errmodel.Code
}

func (s *Service) emailChannel() contactChannel {
	return contactChannel{
		validate:        contact.ValidateEmail,
		normalize:       contact.NormalizeEmail,
		senderAvailable: s.svc.HasEmailSender,
		requestVerification: func(ctx context.Context, id string) error {
			return s.svc.RequestEmailVerification(ctx, id, 0)
		},
		requestChange: s.svc.RequestEmailChange,
		requestPasswordReset: func(ctx context.Context, id string, ip, ua *string) error {
			return s.svc.RequestPasswordReset(ctx, id, 0, ip, ua)
		},
		errUnavailable: errmodel.CodeEmailUnavailable,
	}
}

func (s *Service) phoneChannel() contactChannel {
	return contactChannel{
		validate:        contact.ValidatePhone,
		normalize:       contact.NormalizePhone,
		senderAvailable: s.svc.SMSAvailable,
		requestVerification: func(ctx context.Context, id string) error {
			return s.svc.RequestPhoneVerification(ctx, id, 0)
		},
		requestChange: s.svc.RequestPhoneChange,
		requestPasswordReset: func(ctx context.Context, id string, ip, ua *string) error {
			return s.svc.RequestPhonePasswordReset(ctx, id, 0, ip, ua)
		},
		errUnavailable: errmodel.CodeSMSUnavailable,
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
		fail(w, errmodel.CodeInvalidRequest)
		return contactChannel{}, "", false
	}
	ch, id, err := s.contactChannelFor(identifier)
	if err != nil {
		writeError(w, err)
		return contactChannel{}, "", false
	}
	return ch, id, true
}

// POST /verify/request — {identifier, password?}. Anonymous: 202 for every
// well-formed identifier; a code/link goes only to an unproven account or
// pending registration, so the answer never reveals either. Authenticated:
// start a fresh-auth-gated contact change to identifier.
func (s *Service) handleVerifyRequestPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
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
		writeError(w, errmodel.E(ch.errUnavailable))
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
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	in := authflow.VerificationInput{Identifier: strings.TrimSpace(req.Identifier), Code: strings.ToUpper(strings.TrimSpace(req.Code)), Token: strings.TrimSpace(req.Token), UserAgent: r.UserAgent(), IP: s.requestIP(r)}
	if in.Token != "" && in.Code != "" || in.Token == "" && in.Code == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if in.Identifier != "" || in.Token == "" {
		_, id, ok := s.requireContactChannel(w, in.Identifier)
		if !ok {
			return
		}
		in.Identifier = id
		if s.rateLimitedByIdentifier(w, r, RLVerifyConfirm, id) {
			return
		}
	}
	if claims, ok := verify.ClaimsFromContext(r.Context()); ok {
		in.UserID, in.SessionID = claims.UserID, claims.SessionID
	}
	out, err := s.svc.ConfirmVerification(r.Context(), in)
	if err != nil {
		switch {
		case !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, jwt.ErrTokenInvalidClaims):
			writeError(w, err)
		case in.Token == "":
			fail(w, errmodel.CodeInvalidCode)
		default:
			// One answer for every failed link: it never tells whether the
			// address has an account or is already verified (N9).
			fail(w, errmodel.CodeInvalidLink)
		}
		return
	}
	if out.Kind == authflow.LoginContactChanged {
		noContent(w)
		return
	}
	if s.writeLoginContinuation(w, r, out, nil) {
		return
	}
	s.writeTokenSet(w, r, http.StatusOK, out.Session.TokenSet())
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
		writeError(w, errmodel.E(ch.errUnavailable))
		return
	}
	ua, ip := r.UserAgent(), s.requestIP(r)
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
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.svc.ConfirmPasswordReset(r.Context(), strings.TrimSpace(req.Token), req.NewPassword); err != nil {
		if authflow.ValidationErrorCode(err) != "" {
			writeError(w, err)
			return
		}
		if s.confirmBackendFailed(w, r, "password_reset_confirm", "confirm_password_reset", err) {
			return
		}
		fail(w, errmodel.CodeInvalidLink)
		return
	}
	noContent(w)
}
