package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	passwordlessModeCode = "code"
	passwordlessModeLink = "link"
	passwordlessModeBoth = "both"

	passwordlessChannelEmail = "email"
	passwordlessChannelSMS   = "sms"

	defaultPasswordlessTTL = 10 * time.Minute

	keyPasswordless         = "passwordless:challenge:" // +<handle>
	keyPasswordlessLink     = "passwordless:link:"      // +<linkHash> -> handle
	keyPasswordlessFailures = "passwordless:failures:"  // +<handle>
	// The text's spends of the unconfirmed-text budgets, given back when its
	// code is proven. Apart from the challenge, which is claimed once and
	// never written again.
	keyPasswordlessSMS = "passwordless:sms:" // +<handle>
)

type passwordlessChallenge struct {
	Version           int64 `json:"version,omitempty"`
	handle            string
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

func (s *Engine) StartPasswordless(ctx context.Context, req authflow.PasswordlessStartRequest) (authflow.PasswordlessStartResult, error) {
	if token := strings.TrimSpace(req.AccountInviteToken); token != "" {
		var err error
		ctx, err = s.proofContext(ctx, "registration-invite", secret.Hash(token))
		if err != nil {
			return authflow.PasswordlessStartResult{}, err
		}
	}
	if s == nil || !config.Mounted(s.cfg, iam.RoutePasswordless) {
		return authflow.PasswordlessStartResult{}, errmodel.ErrPasswordlessDisabled
	}
	if s.pg == nil {
		return authflow.PasswordlessStartResult{}, s.requirePG()
	}
	if !s.useEphemeralStore() {
		return authflow.PasswordlessStartResult{}, jwt.ErrTokenUnverifiable
	}
	channel, identifier, err := normalizePasswordlessIdentifier(req.Identifier)
	if err != nil {
		return authflow.PasswordlessStartResult{}, err
	}
	// Before the account lookup, so an unavailable channel answers every
	// identifier alike.
	switch {
	case channel == passwordlessChannelEmail && !s.EmailAvailable():
		return authflow.PasswordlessStartResult{}, errmodel.ErrEmailUnavailable
	case channel == passwordlessChannelSMS && !s.SMSAvailable():
		return authflow.PasswordlessStartResult{}, errmodel.ErrSMSUnavailable
	case channel == passwordlessChannelSMS:
		if _, err := s.smsRegion(identifier); err != nil {
			return authflow.PasswordlessStartResult{}, err
		}
	}
	ctx = contextWithAccountRegistrationInviteToken(ctx, req.AccountInviteToken)
	mode := normalizePasswordlessMode(req.Mode)
	language, err := authflow.NormalizePreferredLanguage(req.PreferredLanguage)
	if err != nil {
		return authflow.PasswordlessStartResult{}, err
	}

	result := authflow.PasswordlessStartResult{Challenge: newChallengeHandle(), Channel: channel}
	var user *db.User
	switch channel {
	case passwordlessChannelEmail:
		user, err = s.getUserByEmail(ctx, identifier)
	case passwordlessChannelSMS:
		user, err = s.getUserByPhone(ctx, identifier)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authflow.PasswordlessStartResult{}, err
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
			return authflow.PasswordlessStartResult{}, err
		}
		contact := version.Email
		if channel == passwordlessChannelSMS {
			contact = version.PhoneNumber
		}
		if contact == nil || *contact != identifier {
			return authflow.PasswordlessStartResult{}, jwt.ErrTokenUnverifiable
		}
		rec.Version = version.CredentialVersion
		rec.UserID = user.ID
	} else {
		if !s.passwordlessAutoRegistrationAllowed() {
			return result, nil
		}
		allowed, err := s.registrationAllowedForEmail(ctx, identifier)
		if err != nil {
			return authflow.PasswordlessStartResult{}, err
		}
		if !allowed {
			return authflow.PasswordlessStartResult{}, errmodel.ErrRegistrationDisabled
		}
		rec.GeneratedUsername, err = s.GenerateUsername(ctx)
		if err != nil {
			return authflow.PasswordlessStartResult{}, err
		}
	}

	if !s.admitCode(ctx, httpapi.RLPasswordlessStartIdentifier, identifier) {
		return result, nil
	}
	code := ""
	linkToken := ""
	if mode == passwordlessModeCode || mode == passwordlessModeBoth {
		code = secret.Digits(6)
		rec.CodeHash = secret.Hash(code)
	}
	if mode == passwordlessModeLink || mode == passwordlessModeBoth {
		linkToken = secret.Token(32)
		rec.LinkHash = secret.Hash(linkToken)
	}
	rec.handle = result.Challenge
	if err := s.storePasswordlessChallenge(ctx, rec); err != nil {
		return authflow.PasswordlessStartResult{}, err
	}

	linkURL := ""
	if linkToken != "" {
		linkURL = s.passwordlessURL(channel, linkToken, rec.ReturnTo)
	}
	sendCtx, receipt := withSMSReceipt(ctx)
	if err := s.sendPasswordlessChallenge(sendCtx, rec, code, linkURL); err != nil {
		s.deletePasswordlessChallenge(ctx, rec)
		if withheld(err) {
			return result, nil
		}
		return authflow.PasswordlessStartResult{}, err
	}
	if len(*receipt) > 0 {
		// Best effort: without it the text stays counted.
		_ = s.ephemSetJSON(ctx, keyPasswordlessSMS+rec.handle, *receipt, defaultPasswordlessTTL)
	}
	result.Sent, result.Code, result.LinkURL = true, code, linkURL
	return result, nil
}

func (s *Engine) PasswordlessLogin(ctx context.Context, in authflow.PasswordlessLoginInput) (authflow.LoginOutcome, error) {
	if s == nil || !config.Mounted(s.cfg, iam.RoutePasswordless) {
		return authflow.LoginOutcome{}, errmodel.ErrPasswordlessDisabled
	}
	if !s.useEphemeralStore() {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	var rec passwordlessChallenge
	var ok bool
	var err error
	switch {
	case in.Token != "" && in.Code == "":
		hash := secret.Hash(in.Token)
		ctx, err = s.proofContext(ctx, "passwordless-link", hash)
		if err != nil {
			return authflow.LoginOutcome{}, err
		}
		handle, found, lookupErr := s.ephemGetString(ctx, keyPasswordlessLink+hash)
		if lookupErr != nil {
			return authflow.LoginOutcome{}, lookupErr
		}
		if !found {
			return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
		rec, ok, err = s.loadPasswordlessChallenge(ctx, handle)
		if err != nil {
			return authflow.LoginOutcome{}, err
		}
		if !ok || !secret.Equal(rec.LinkHash, hash) {
			return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
		if in.Identifier != "" && !rec.names(in.Identifier) {
			return authflow.LoginOutcome{}, jwt.ErrTokenInvalidClaims
		}
	case in.Token == "" && in.Challenge != "" && in.Code != "":
		rec, ok, err = s.loadPasswordlessChallenge(ctx, in.Challenge)
		if err != nil {
			return authflow.LoginOutcome{}, err
		}
		if !ok {
			return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
		if rec.CodeHash == "" || !secret.Equal(rec.CodeHash, secret.Hash(in.Code)) || in.Identifier != "" && !rec.names(in.Identifier) {
			if s.recordFailedAttempt(ctx, keyPasswordlessFailures+rec.handle, defaultPasswordlessTTL, maxChallengeFailures) {
				s.deletePasswordlessChallenge(ctx, rec)
			}
			return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
	default:
		return authflow.LoginOutcome{}, jwt.ErrTokenInvalidClaims
	}
	// A sign-up accepts its agreements before the code is spent, so the
	// retry that accepts them reuses it.
	var agreements []iam.AgreementRef
	if rec.UserID == "" {
		if agreements, err = s.acceptable(in.Agreements); err != nil {
			return authflow.LoginOutcome{}, err
		}
		if err := s.requireRegistrationAgreements(agreements); err != nil {
			return authflow.LoginOutcome{}, err
		}
	}
	account, err := s.consumePasswordlessChallenge(ctx, rec, accountRegistration{Agreements: agreements, IP: in.IP, UserAgent: in.UserAgent})
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	var spends []smsSpend
	if ok, _ := s.ephemConsumeJSON(ctx, keyPasswordlessSMS+rec.handle, &spends); ok {
		s.refundSMS(ctx, spends)
	}
	method := "email"
	if rec.Channel == passwordlessChannelSMS {
		method = "sms"
	}
	return s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), ReturnTo: rec.ReturnTo, Created: rec.UserID == "", Input: loginSessionInput{UserID: account.ID, AuthMethods: []string{method}, Event: passwordlessSessionMethod(rec.Channel), UserAgent: in.UserAgent, IP: in.IP}})
}

// names reports whether identifier is the address rec's code went to.
func (rec passwordlessChallenge) names(identifier string) bool {
	channel, normalized, err := normalizePasswordlessIdentifier(identifier)
	return err == nil && channel == rec.Channel && normalized == rec.Identifier
}

// storePasswordlessChallenge stores rec under its handle; it replaces no
// other start. Only the 256-bit link token gets a global pointer.
func (s *Engine) storePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge) error {
	key := keyPasswordless + rec.handle
	if err := s.ephemSetJSON(ctx, key, rec, defaultPasswordlessTTL); err != nil {
		return err
	}
	if rec.LinkHash != "" {
		if err := s.ephemSetString(ctx, keyPasswordlessLink+rec.LinkHash, rec.handle, defaultPasswordlessTTL); err != nil {
			return err
		}
		return s.rememberProofRoute(ctx, "passwordless-link", rec.LinkHash, defaultPasswordlessTTL)
	}
	return nil
}

func (s *Engine) loadPasswordlessChallenge(ctx context.Context, handle string) (passwordlessChallenge, bool, error) {
	var rec passwordlessChallenge
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return rec, false, nil
	}
	raw, ok, err := s.ephemReadJSON(ctx, keyPasswordless+handle, &rec)
	rec.handle, rec.expected = handle, raw
	return rec, ok && rec.Channel != "", err
}

// deletePasswordlessChallenge burns rec: its code, link and failure count.
func (s *Engine) deletePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge) {
	_ = s.ephemDel(ctx, keyPasswordless+rec.handle)
	_ = s.ephemDel(ctx, keyPasswordlessFailures+rec.handle)
	if rec.LinkHash != "" {
		_ = s.ephemDel(ctx, keyPasswordlessLink+rec.LinkHash)
	}
}

// consumePasswordlessChallenge spends rec: a sign-in, or a sign-up with
// signup's agreements and client.
func (s *Engine) consumePasswordlessChallenge(ctx context.Context, rec passwordlessChallenge, signup accountRegistration) (registeredAccount, error) {
	if err := s.claimProof(ctx, keyPasswordless+rec.handle, rec.expected); err != nil {
		return registeredAccount{}, err
	}
	s.deletePasswordlessChallenge(ctx, rec)
	if rec.UserID == "" {
		if !s.passwordlessAutoRegistrationAllowed() {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
		return s.createPasswordlessUser(ctx, rec, signup)
	}
	return s.verifyContactProofWithRecovery(ctx, rec.UserID, rec.Version, rec.Channel, rec.Identifier, true, nil, 0)
}

func (s *Engine) verifyContactProof(ctx context.Context, userID string, version int64, channel, identifier string, keepSessionID *string) (registeredAccount, error) {
	return s.verifyContactProofWithRecovery(ctx, userID, version, channel, identifier, false, keepSessionID, 0)
}

// Only a login completion can verify a deleted account's contact before the
// recovery tail. Standalone contact finalizers retain the normal access gate.
// keepSessionID is the authenticated session presenting the proof, if any, and
// passwordVersion the credential version a spent password proof holds (0 for
// none); see retirePreProofCredentials.
func (s *Engine) verifyContactProofWithRecovery(ctx context.Context, userID string, version int64, channel, identifier string, allowRecovery bool, keepSessionID *string, passwordVersion int64) (registeredAccount, error) {
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
	case passwordlessChannelEmail:
		if u.Email == nil || *u.Email != identifier {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
	case passwordlessChannelSMS:
		if u.PhoneNumber == nil || *u.PhoneNumber != identifier {
			return registeredAccount{}, jwt.ErrTokenUnverifiable
		}
	default:
		return registeredAccount{}, jwt.ErrTokenInvalidClaims
	}
	p := proofOn(channel)
	// The proof held for this password: no credential change since it.
	p.password = passwordVersion > 0 && passwordVersion == u.CredentialVersion
	revoked, err := s.retirePreProofCredentials(ctx, tx, iam.UserIdentity(u.ID), u.ID, p, keepSessionID)
	if err != nil {
		return registeredAccount{}, err
	}
	switch channel {
	case passwordlessChannelEmail:
		err = q.UserSetEmailVerified(ctx, db.UserSetEmailVerifiedParams{ID: u.ID, EmailVerified: true})
	case passwordlessChannelSMS:
		err = q.UserSetPhoneVerifiedByIDAndPhone(ctx, db.UserSetPhoneVerifiedByIDAndPhoneParams{ID: u.ID, PhoneNumber: &identifier})
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
	s.logRevokedSessions(ctx, u.ID, revoked, string(authflow.SessionRevokeReasonContactProven))
	return registeredAccount{ID: u.ID, Version: current.CredentialVersion}, nil
}

func (s *Engine) createPasswordlessUser(ctx context.Context, rec passwordlessChallenge, signup accountRegistration) (registeredAccount, error) {
	username := rec.GeneratedUsername
	if username == "" || s.ValidateUsername(username) != nil {
		var err error
		username, err = s.GenerateUsername(ctx)
		if err != nil {
			return registeredAccount{}, err
		}
	}
	in := newAccount{Username: username}
	switch rec.Channel {
	case passwordlessChannelEmail:
		in.Email = rec.Identifier
		in.EmailVerified = true
	case passwordlessChannelSMS:
		in.PhoneNumber = rec.Identifier
		in.PhoneVerified = true
	default:
		return registeredAccount{}, jwt.ErrTokenInvalidClaims
	}
	// A signup proof stays a signup: a uniqueness race never changes it into
	// an existing-account login that skips its invitation/admission checks.
	signup.User, signup.Language, signup.InviteToken, signup.GeneratedUsername = in, rec.PreferredLanguage, rec.AccountInviteToken, true
	user, err := s.registerAccount(ctx, signup)
	if err != nil {
		return registeredAccount{}, err
	}
	return user, nil
}

func (s *Engine) sendPasswordlessChallenge(ctx context.Context, rec passwordlessChallenge, code, linkURL string) error {
	language := s.messageLanguage(ctx, rec.PreferredLanguage)
	switch rec.Channel {
	case passwordlessChannelEmail:
		return s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageVerification, To: rec.Identifier, Username: rec.GeneratedUsername,
			Language: language, Code: code, Link: linkURL, Purpose: iam.PurposePasswordlessLogin})
	case passwordlessChannelSMS:
		return s.sendSMS(ctx, iam.SMSMessage{Kind: iam.MessageVerification, To: rec.Identifier, UserID: rec.UserID,
			Language: language, Code: code, Link: linkURL, Purpose: iam.PurposePasswordlessLogin})
	default:
		return jwt.ErrTokenInvalidClaims
	}
}

func (s *Engine) passwordlessAutoRegistrationAllowed() bool {
	// A verified contact signing up, when registration admits it (an
	// invite-only one checks the invitation).
	return s != nil && s.cfg.Registration != iam.RegistrationModeClosed
}

func normalizePasswordlessIdentifier(identifier string) (channel, normalized string, err error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "", "", jwt.ErrTokenInvalidClaims
	}
	if strings.Contains(identifier, "@") {
		normalized = contact.NormalizeEmail(identifier)
		if err := contact.ValidateEmail(normalized); err != nil {
			return "", "", err
		}
		return passwordlessChannelEmail, normalized, nil
	}
	normalized = contact.NormalizePhone(identifier)
	if err := contact.ValidatePhone(normalized); err != nil {
		return "", "", err
	}
	return passwordlessChannelSMS, normalized, nil
}

func normalizePasswordlessMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case passwordlessModeCode:
		return passwordlessModeCode
	case passwordlessModeLink:
		return passwordlessModeLink
	default:
		return passwordlessModeBoth
	}
}

func passwordlessSessionMethod(channel string) string {
	if channel == passwordlessChannelSMS {
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
