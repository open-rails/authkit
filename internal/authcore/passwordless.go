package authcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
)

const (
	PasswordlessModeCode = "code"
	PasswordlessModeLink = "link"
	PasswordlessModeBoth = "both"

	PasswordlessChannelEmail = "email"
	PasswordlessChannelSMS   = "sms"

	defaultPasswordlessTTL = 10 * time.Minute

	keyPasswordlessToken    = "auth:passwordless:token:"
	keyPasswordlessTarget   = "auth:passwordless:target:"
	keyPasswordlessAttempts = "auth:passwordless:attempts:"
)

type PasswordlessStartRequest struct {
	Identifier        string
	Mode              string
	ReturnTo          string
	PreferredLanguage string
}

type PasswordlessStartResult struct {
	Sent    bool
	Channel string
	Code    string
	LinkURL string
}

type PasswordlessConfirmResult struct {
	UserID   string
	Method   string
	ReturnTo string
}

type passwordlessChallenge struct {
	Channel           string   `json:"channel"`
	Identifier        string   `json:"identifier"`
	UserID            string   `json:"user_id,omitempty"`
	GeneratedUsername string   `json:"generated_username,omitempty"`
	PreferredLanguage string   `json:"preferred_language,omitempty"`
	ReturnTo          string   `json:"return_to,omitempty"`
	TokenHashes       []string `json:"token_hashes,omitempty"`
}

func (s *Service) StartPasswordless(ctx context.Context, req PasswordlessStartRequest) (PasswordlessStartResult, error) {
	if s == nil || !s.opts.PasswordlessLoginEnabled {
		return PasswordlessStartResult{}, ErrPasswordlessDisabled
	}
	if s.pg == nil {
		return PasswordlessStartResult{}, s.requirePG()
	}
	if !s.useEphemeralStore() {
		return PasswordlessStartResult{}, jwt.ErrTokenUnverifiable
	}
	channel, identifier, err := normalizePasswordlessIdentifier(req.Identifier)
	if err != nil {
		return PasswordlessStartResult{}, err
	}
	mode := normalizePasswordlessMode(req.Mode)
	language, err := NormalizePreferredLanguage(req.PreferredLanguage)
	if err != nil {
		return PasswordlessStartResult{}, err
	}

	var user *User
	switch channel {
	case PasswordlessChannelEmail:
		user, err = s.getUserByEmail(ctx, identifier)
	case PasswordlessChannelSMS:
		user, err = s.getUserByPhone(ctx, identifier)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return PasswordlessStartResult{}, err
	}

	rec := passwordlessChallenge{
		Channel:           channel,
		Identifier:        identifier,
		PreferredLanguage: language,
		ReturnTo:          sanitizePasswordlessReturnTo(req.ReturnTo),
	}
	if user != nil {
		rec.UserID = user.ID
	} else {
		if !s.passwordlessAutoRegistrationAllowed() {
			return PasswordlessStartResult{Channel: channel}, nil
		}
		rec.GeneratedUsername = s.derivePasswordlessUsername(ctx, channel, identifier)
	}

	code := ""
	linkToken := ""
	tokenTTLs := map[string]time.Duration{}
	if mode == PasswordlessModeCode || mode == PasswordlessModeBoth {
		code = randAlphanumeric(6)
		tokenTTLs[sha256Hex(code)] = defaultPasswordlessTTL
	}
	if mode == PasswordlessModeLink || mode == PasswordlessModeBoth {
		linkToken = randB64(32)
		tokenTTLs[sha256Hex(linkToken)] = defaultPasswordlessTTL
	}
	if len(tokenTTLs) == 0 {
		return PasswordlessStartResult{}, jwt.ErrTokenInvalidClaims
	}
	if err := s.storePasswordlessChallenge(ctx, rec, tokenTTLs); err != nil {
		return PasswordlessStartResult{}, err
	}

	linkURL := ""
	if linkToken != "" {
		linkURL = s.passwordlessURL(channel, linkToken, rec.ReturnTo)
	}
	if err := s.sendPasswordlessChallenge(ctx, rec, code, linkURL); err != nil {
		return PasswordlessStartResult{}, err
	}
	return PasswordlessStartResult{Sent: true, Channel: channel, Code: code, LinkURL: linkURL}, nil
}

func (s *Service) ConfirmPasswordlessCode(ctx context.Context, identifier, code string) (PasswordlessConfirmResult, error) {
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	if err != nil {
		return PasswordlessConfirmResult{}, err
	}
	tokenHash := sha256Hex(code)
	rec, ok, err := s.loadPasswordlessChallenge(ctx, tokenHash)
	if err != nil || !ok {
		return PasswordlessConfirmResult{}, jwt.ErrTokenUnverifiable
	}
	if rec.Channel != channel || !strings.EqualFold(rec.Identifier, normalized) {
		return PasswordlessConfirmResult{}, jwt.ErrTokenInvalidClaims
	}
	result, err := s.consumePasswordlessChallenge(ctx, tokenHash, rec)
	if err == nil {
		s.ClearPasswordlessCodeAttempts(ctx, identifier)
	}
	return result, err
}

func (s *Service) ConfirmPasswordlessToken(ctx context.Context, token string) (PasswordlessConfirmResult, error) {
	tokenHash := sha256Hex(token)
	rec, ok, err := s.loadPasswordlessChallenge(ctx, tokenHash)
	if err != nil || !ok {
		return PasswordlessConfirmResult{}, jwt.ErrTokenUnverifiable
	}
	return s.consumePasswordlessChallenge(ctx, tokenHash, rec)
}

func (s *Service) storePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge, tokenTTLs map[string]time.Duration) error {
	normalizedTTLs, canonicalHash, maxTTL, err := normalizeTokenTTLs(tokenTTLs, defaultPasswordlessTTL)
	if err != nil {
		return err
	}
	s.deletePasswordlessByTarget(ctx, rec.Channel, rec.Identifier)
	rec.TokenHashes = uniqueTokenHashes(canonicalHash, nil)
	for tokenHash := range normalizedTTLs {
		rec.TokenHashes = uniqueTokenHashes(tokenHash, rec.TokenHashes)
	}
	for tokenHash, ttl := range normalizedTTLs {
		if err := s.ephemSetJSON(ctx, keyPasswordlessToken+tokenHash, rec, ttl); err != nil {
			return err
		}
	}
	_ = s.ephemSetString(ctx, passwordlessTargetKey(rec.Channel, rec.Identifier), canonicalHash, maxTTL)
	return nil
}

func (s *Service) loadPasswordlessChallenge(ctx context.Context, tokenHash string) (passwordlessChallenge, bool, error) {
	var rec passwordlessChallenge
	ok, err := s.ephemGetJSON(ctx, keyPasswordlessToken+tokenHash, &rec)
	return rec, ok, err
}

func (s *Service) deletePasswordlessByToken(ctx context.Context, tokenHash string) {
	rec, ok, _ := s.loadPasswordlessChallenge(ctx, tokenHash)
	if !ok {
		_ = s.ephemDel(ctx, keyPasswordlessToken+tokenHash)
		return
	}
	for _, h := range uniqueTokenHashes(tokenHash, rec.TokenHashes) {
		_ = s.ephemDel(ctx, keyPasswordlessToken+h)
	}
	_ = s.ephemDel(ctx, passwordlessTargetKey(rec.Channel, rec.Identifier))
}

func (s *Service) deletePasswordlessByTarget(ctx context.Context, channel, identifier string) {
	if token, ok, _ := s.ephemGetString(ctx, passwordlessTargetKey(channel, identifier)); ok && token != "" {
		s.deletePasswordlessByToken(ctx, token)
	}
}

func (s *Service) RecordFailedPasswordlessCode(ctx context.Context, identifier string) {
	if !s.useEphemeralStore() {
		return
	}
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	if err != nil {
		return
	}
	key := keyPasswordlessAttempts + channel + ":" + normalized
	n := 0
	if v, ok, _ := s.ephemGetString(ctx, key); ok {
		_, _ = fmt.Sscanf(v, "%d", &n)
	}
	n++
	if n >= maxEmailVerifyCodeAttempts {
		s.deletePasswordlessByTarget(ctx, channel, normalized)
		_ = s.ephemDel(ctx, key)
		return
	}
	_ = s.ephemSetString(ctx, key, fmt.Sprintf("%d", n), defaultPasswordlessTTL)
}

func (s *Service) ClearPasswordlessCodeAttempts(ctx context.Context, identifier string) {
	if !s.useEphemeralStore() {
		return
	}
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	if err != nil {
		return
	}
	_ = s.ephemDel(ctx, keyPasswordlessAttempts+channel+":"+normalized)
}

func (s *Service) consumePasswordlessChallenge(ctx context.Context, tokenHash string, rec passwordlessChallenge) (PasswordlessConfirmResult, error) {
	userID := strings.TrimSpace(rec.UserID)
	if userID != "" {
		if err := s.verifyPasswordlessExistingUser(ctx, rec); err != nil {
			return PasswordlessConfirmResult{}, err
		}
	} else {
		if !s.passwordlessAutoRegistrationAllowed() {
			return PasswordlessConfirmResult{}, jwt.ErrTokenUnverifiable
		}
		var err error
		userID, err = s.createPasswordlessUser(ctx, rec)
		if err != nil {
			return PasswordlessConfirmResult{}, err
		}
	}
	s.deletePasswordlessByToken(ctx, tokenHash)
	return PasswordlessConfirmResult{
		UserID:   userID,
		Method:   passwordlessSessionMethod(rec.Channel),
		ReturnTo: rec.ReturnTo,
	}, nil
}

func (s *Service) verifyPasswordlessExistingUser(ctx context.Context, rec passwordlessChallenge) error {
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return errOrUnauthorized(err)
	}
	if err := s.ensureUserAccess(ctx, u); err != nil {
		return err
	}
	switch rec.Channel {
	case PasswordlessChannelEmail:
		if u.Email == nil || !strings.EqualFold(NormalizeEmail(*u.Email), rec.Identifier) {
			return jwt.ErrTokenInvalidClaims
		}
		return s.setEmailVerified(ctx, rec.UserID, true)
	case PasswordlessChannelSMS:
		if u.PhoneNumber == nil || NormalizePhone(*u.PhoneNumber) != rec.Identifier {
			return jwt.ErrTokenInvalidClaims
		}
		return s.setPhoneVerified(ctx, rec.UserID, true)
	default:
		return jwt.ErrTokenInvalidClaims
	}
}

func (s *Service) createPasswordlessUser(ctx context.Context, rec passwordlessChallenge) (string, error) {
	username := rec.GeneratedUsername
	if username == "" {
		username = s.derivePasswordlessUsername(ctx, rec.Channel, rec.Identifier)
	}
	if _, err := s.ValidateUsernameForRegistration(ctx, username); err != nil {
		username = s.derivePasswordlessUsername(ctx, rec.Channel, rec.Identifier)
	}
	switch rec.Channel {
	case PasswordlessChannelEmail:
		if existing, _ := s.getUserByEmail(ctx, rec.Identifier); existing != nil {
			return existing.ID, s.setEmailVerified(ctx, existing.ID, true)
		}
		u, err := s.createUser(ctx, rec.Identifier, username)
		if err != nil {
			return "", err
		}
		if u == nil {
			return "", fmt.Errorf("failed to create user")
		}
		if err := s.setEmailVerified(ctx, u.ID, true); err != nil {
			return "", err
		}
		if rec.PreferredLanguage != "" {
			_ = s.SetPreferredLanguage(ctx, u.ID, rec.PreferredLanguage)
		}
		return u.ID, nil
	case PasswordlessChannelSMS:
		if existing, _ := s.getUserByPhone(ctx, rec.Identifier); existing != nil {
			return existing.ID, s.setPhoneVerified(ctx, existing.ID, true)
		}
		u, err := s.createUser(ctx, "", username)
		if err != nil {
			return "", err
		}
		if u == nil {
			return "", fmt.Errorf("failed to create user")
		}
		phone := rec.Identifier
		if err := s.q.UserSetPhoneAndVerified(ctx, db.UserSetPhoneAndVerifiedParams{ID: u.ID, PhoneNumber: &phone, PhoneVerified: true}); err != nil {
			return "", err
		}
		if rec.PreferredLanguage != "" {
			_ = s.SetPreferredLanguage(ctx, u.ID, rec.PreferredLanguage)
		}
		return u.ID, nil
	default:
		return "", jwt.ErrTokenInvalidClaims
	}
}

func (s *Service) sendPasswordlessChallenge(ctx context.Context, rec passwordlessChallenge, code, linkURL string) error {
	msg := VerificationMessage{Code: code, LinkURL: linkURL, Purpose: "passwordless_login"}
	if err := msg.Validate(); err != nil {
		return err
	}
	sendCtx := contextWithPreferredLanguage(ctx, rec.PreferredLanguage)
	switch rec.Channel {
	case PasswordlessChannelEmail:
		if s.email == nil {
			return ErrEmailSenderUnavailable
		}
		return emailDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
			return s.email.SendVerification(sendCtx, rec.Identifier, rec.GeneratedUsername, msg)
		}))
	case PasswordlessChannelSMS:
		if s.sms == nil || !s.SMSAvailable() {
			return ErrSMSSenderUnavailable
		}
		return smsDeliveryError(s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
			return s.sms.SendVerification(sendCtx, rec.Identifier, msg)
		}))
	default:
		return jwt.ErrTokenInvalidClaims
	}
}

func (s *Service) passwordlessAutoRegistrationAllowed() bool {
	return s != nil && s.opts.PasswordlessAutoRegistrationEnabled && s.opts.PublicNativeUserRegistrationEnabled()
}

func (s *Service) derivePasswordlessUsername(ctx context.Context, channel, identifier string) string {
	base := "user"
	if channel == PasswordlessChannelEmail {
		if at := strings.IndexByte(identifier, '@'); at > 0 {
			base = identifier[:at]
		}
	} else if channel == PasswordlessChannelSMS {
		base = "u" + strings.TrimLeft(strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, identifier), "0")
	}
	return s.GenerateAvailableUsername(ctx, base)
}

func normalizePasswordlessIdentifier(identifier string) (channel, normalized string, err error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", "", jwt.ErrTokenInvalidClaims
	}
	if strings.Contains(identifier, "@") {
		normalized = NormalizeEmail(identifier)
		if err := ValidateEmail(normalized); err != nil {
			return "", "", err
		}
		return PasswordlessChannelEmail, normalized, nil
	}
	normalized = NormalizePhone(identifier)
	if err := ValidatePhone(normalized); err != nil {
		return "", "", err
	}
	return PasswordlessChannelSMS, normalized, nil
}

func normalizePasswordlessMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case PasswordlessModeCode:
		return PasswordlessModeCode
	case PasswordlessModeLink:
		return PasswordlessModeLink
	default:
		return PasswordlessModeBoth
	}
}

func passwordlessTargetKey(channel, identifier string) string {
	return keyPasswordlessTarget + channel + ":" + identifier
}

func passwordlessSessionMethod(channel string) string {
	if channel == PasswordlessChannelSMS {
		return "passwordless_sms"
	}
	return "passwordless_email"
}

func sanitizePasswordlessReturnTo(returnTo string) string {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		return ""
	}
	return returnTo
}
