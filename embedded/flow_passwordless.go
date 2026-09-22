package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"

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

	keyPasswordless         = "passwordless:rec:"  // +<channel>:<identifier>
	keyPasswordlessLink     = "passwordless:link:" // +<linkHash> -> record key
	keyPasswordlessAttempts = "passwordless:attempts:"
)

type PasswordlessStartRequest = authkit.PasswordlessStartRequest

type PasswordlessStartResult = authkit.PasswordlessStartResult

type passwordlessChallenge struct {
	Version           int64  `json:"version,omitempty"`
	ID                string `json:"id"`
	expected          []byte
	Channel           string `json:"channel"`
	Identifier        string `json:"identifier"`
	UserID            string `json:"user_id,omitempty"`
	GeneratedUsername string `json:"generated_username,omitempty"`
	PreferredLanguage string `json:"preferred_language,omitempty"`
	ReturnTo          string `json:"return_to,omitempty"`
	CodeHash          string `json:"code_hash,omitempty"`
	LinkHash          string `json:"link_hash,omitempty"`
	// AccountInviteToken carries the unbound single-use account-registration code
	// from start to confirm (#147): the code is the credential, so it must be
	// present at consume time, which happens at confirm (when the user id exists).
	AccountInviteToken string `json:"account_invite_token,omitempty"`
}

func (s *engine) StartPasswordless(ctx context.Context, req PasswordlessStartRequest) (PasswordlessStartResult, error) {
	if s == nil || !s.cfg.Registration.PasswordlessLogin {
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
	ctx = contextWithAccountRegistrationInviteToken(ctx, req.AccountInviteToken)
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
		Channel:            channel,
		Identifier:         identifier,
		PreferredLanguage:  language,
		ReturnTo:           sanitizePasswordlessReturnTo(req.ReturnTo),
		AccountInviteToken: strings.TrimSpace(req.AccountInviteToken),
	}
	if user != nil {
		version, err := s.q.UserCredentialVersion(ctx, user.ID)
		if err != nil {
			return PasswordlessStartResult{}, err
		}
		contact := version.Email
		if channel == PasswordlessChannelSMS {
			contact = version.PhoneNumber
		}
		if contact == nil || *contact != identifier {
			return PasswordlessStartResult{}, jwt.ErrTokenUnverifiable
		}
		rec.Version = version.CredentialVersion
		rec.UserID = user.ID
	} else {
		if !s.passwordlessAutoRegistrationAllowed() {
			return PasswordlessStartResult{Channel: channel}, nil
		}
		allowed, err := s.registrationAllowedForEmail(ctx, identifier)
		if err != nil {
			return PasswordlessStartResult{}, err
		}
		if !allowed {
			return PasswordlessStartResult{}, ErrRegistrationDisabled
		}
		rec.GeneratedUsername = s.derivePasswordlessUsername(ctx, channel, identifier)
	}

	code := ""
	linkToken := ""
	if mode == PasswordlessModeCode || mode == PasswordlessModeBoth {
		code = randAlphanumeric(6)
		rec.CodeHash = sha256Hex(code)
	}
	if mode == PasswordlessModeLink || mode == PasswordlessModeBoth {
		linkToken = RandB64(32)
		rec.LinkHash = sha256Hex(linkToken)
	}
	if err := s.storePasswordlessChallenge(ctx, rec); err != nil {
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

// PasswordlessLoginInput selects either a typed code or a link token, never
// both, and supplies request metadata for the resulting authentication.
type PasswordlessLoginInput struct {
	Identifier string
	Code       string
	Token      string
	UserAgent  string
	IP         string
}

func (s *engine) PasswordlessLogin(ctx context.Context, in PasswordlessLoginInput) (LoginOutcome, error) {
	if s == nil || !s.cfg.Registration.PasswordlessLogin {
		return LoginOutcome{}, ErrPasswordlessDisabled
	}
	var rec passwordlessChallenge
	var ok bool
	var err error
	if in.Token != "" && in.Code == "" {
		hash := sha256Hex(in.Token)
		key, found, lookupErr := s.ephemGetString(ctx, keyPasswordlessLink+hash)
		if lookupErr != nil {
			return LoginOutcome{}, lookupErr
		}
		if !found {
			return LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
		rec, ok, err = s.loadPasswordlessChallenge(ctx, key)
		if err != nil {
			return LoginOutcome{}, err
		}
		if !ok || !SecretEqual(rec.LinkHash, hash) {
			return LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
		if in.Identifier != "" {
			channel, identifier, err := normalizePasswordlessIdentifier(in.Identifier)
			if err != nil || channel != rec.Channel || identifier != rec.Identifier {
				return LoginOutcome{}, jwt.ErrTokenInvalidClaims
			}
		}

	} else if in.Token == "" && in.Identifier != "" && in.Code != "" {
		channel, identifier, e := normalizePasswordlessIdentifier(in.Identifier)
		if e != nil {
			return LoginOutcome{}, e
		}
		rec, ok, err = s.loadPasswordlessChallenge(ctx, passwordlessKey(channel, identifier))
		if err != nil {
			return LoginOutcome{}, err
		}
		if !ok || rec.CodeHash == "" || !SecretEqual(rec.CodeHash, sha256Hex(in.Code)) {
			s.RecordFailedPasswordlessCode(ctx, identifier)
			return LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
	} else {
		return LoginOutcome{}, jwt.ErrTokenInvalidClaims
	}
	account, err := s.consumePasswordlessChallenge(ctx, rec)
	if err != nil {
		return LoginOutcome{}, err
	}
	s.clearPasswordlessCodeAttempts(ctx, rec.Identifier)
	method := "email"
	if rec.Channel == PasswordlessChannelSMS {
		method = "sms"
	}
	out, err := s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), ReturnTo: rec.ReturnTo, Input: LoginSessionInput{UserID: account.ID, AuthMethods: []string{method}, Event: passwordlessSessionMethod(rec.Channel), UserAgent: in.UserAgent, IP: in.IP}})
	return out, err
}

// storePasswordlessChallenge issues one challenge per (channel, identifier),
// superseding any outstanding one. The code hash stays inside the record; only
// the 256-bit link token gets a global pointer (#301).
func (s *engine) storePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge) error {
	rec.ID = RandB64(16)
	key := passwordlessKey(rec.Channel, rec.Identifier)
	s.deletePasswordlessChallenge(ctx, key)
	if err := s.ephemSetJSON(ctx, key, rec, defaultPasswordlessTTL); err != nil {
		return err
	}
	if rec.LinkHash != "" {
		return s.ephemSetString(ctx, keyPasswordlessLink+rec.LinkHash, key, defaultPasswordlessTTL)
	}
	return nil
}

func (s *engine) loadPasswordlessChallenge(ctx context.Context, key string) (passwordlessChallenge, bool, error) {
	var rec passwordlessChallenge
	raw, ok, err := s.ephemReadJSON(ctx, key, &rec)
	rec.expected = raw
	return rec, ok && rec.ID != "", err
}

func (s *engine) deletePasswordlessChallenge(ctx context.Context, key string) {
	rec, ok, _ := s.loadPasswordlessChallenge(ctx, key)
	if ok && s.claimProof(ctx, key, rec.expected) == nil && rec.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPasswordlessLink+rec.LinkHash)
	}
}

func (s *engine) deletePasswordlessByTarget(ctx context.Context, channel, identifier string) {
	s.deletePasswordlessChallenge(ctx, passwordlessKey(channel, identifier))
}

func (s *engine) RecordFailedPasswordlessCode(ctx context.Context, identifier string) {
	if !s.useEphemeralStore() {
		return
	}
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	if err != nil {
		return
	}
	if s.recordFailedAttempt(ctx, keyPasswordlessAttempts+channel+":"+normalized, defaultPasswordlessTTL, maxEmailVerifyCodeAttempts) {
		s.deletePasswordlessByTarget(ctx, channel, normalized)
	}
}

func (s *engine) clearPasswordlessCodeAttempts(ctx context.Context, identifier string) {
	if !s.useEphemeralStore() {
		return
	}
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	if err != nil {
		return
	}
	_ = s.ephemDel(ctx, keyPasswordlessAttempts+channel+":"+normalized)
}

func (s *engine) consumePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge) (registeredAccount, error) {
	if err := s.claimProof(ctx, passwordlessKey(rec.Channel, rec.Identifier), rec.expected); err != nil {
		return registeredAccount{}, err
	}
	if rec.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPasswordlessLink+rec.LinkHash)
	}
	if rec.UserID == "" {
		if !s.passwordlessAutoRegistrationAllowed() {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
		return s.createPasswordlessUser(ctx, rec)
	}
	return s.verifyContactProofWithRecovery(ctx, rec.UserID, rec.Version, rec.Channel, rec.Identifier, true)
}

func (s *engine) verifyContactProof(ctx context.Context, userID string, version int64, channel, identifier string) (registeredAccount, error) {
	return s.verifyContactProofWithRecovery(ctx, userID, version, channel, identifier, false)
}

// Only a login completion can verify a deleted account's contact before the
// recovery tail. Standalone contact finalizers retain the normal access gate.
func (s *engine) verifyContactProofWithRecovery(ctx context.Context, userID string, version int64, channel, identifier string, allowRecovery bool) (registeredAccount, error) {
	if version <= 0 {
		return registeredAccount{}, jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return registeredAccount{}, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	u, err := s.lockAuthenticationAccount(ctx, q, userID, version, allowRecovery)
	if err != nil {
		return registeredAccount{}, err
	}
	switch channel {
	case PasswordlessChannelEmail:
		if u.Email == nil || *u.Email != identifier {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
		err = q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: u.ID, EmailVerified: true})
	case PasswordlessChannelSMS:
		if u.PhoneNumber == nil || *u.PhoneNumber != identifier {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
		err = q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: u.ID, PhoneNumber: &identifier})
	default:
		return registeredAccount{}, jwt.ErrTokenInvalidClaims
	}
	if err != nil {
		return registeredAccount{}, err
	}
	current, err := q.UserCredentialVersion(ctx, u.ID)
	if err != nil {
		return registeredAccount{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return registeredAccount{}, err
	}
	return registeredAccount{ID: u.ID, Version: current.CredentialVersion}, nil
}

func (s *engine) createPasswordlessUser(ctx context.Context, rec passwordlessChallenge) (registeredAccount, error) {
	username := rec.GeneratedUsername
	if username == "" || ValidateUsername(username) != nil {
		username = s.derivePasswordlessUsername(ctx, rec.Channel, rec.Identifier)
	}
	in := ImportUserInput{Username: username}
	switch rec.Channel {
	case PasswordlessChannelEmail:
		in.Email = rec.Identifier
		in.EmailVerified = true
	case PasswordlessChannelSMS:
		in.PhoneNumber = rec.Identifier
		in.PhoneVerified = true
	default:
		return registeredAccount{}, jwt.ErrTokenInvalidClaims
	}
	// A signup proof stays a signup: a uniqueness race never changes it into
	// an existing-account login that skips its invitation/admission checks.
	user, err := s.registerAccount(ctx, accountRegistration{User: in, Language: rec.PreferredLanguage, InviteToken: rec.AccountInviteToken})
	if err != nil {
		return registeredAccount{}, err
	}
	return user, nil
}

func (s *engine) sendPasswordlessChallenge(ctx context.Context, rec passwordlessChallenge, code, linkURL string) error {
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

func (s *engine) passwordlessAutoRegistrationAllowed() bool {
	if s == nil || !s.cfg.Registration.PasswordlessAutoRegistration {
		return false
	}
	mode, err := normalizeRegistrationMode(s.cfg.Registration.NativeUserMode)
	return err == nil && mode != RegistrationModeClosed
}

func (s *engine) derivePasswordlessUsername(ctx context.Context, channel, identifier string) string {
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

func passwordlessKey(channel, identifier string) string {
	return keyPasswordless + channel + ":" + identifier
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
