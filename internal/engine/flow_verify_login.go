package engine

import (
	"context"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/secret"
)

// verificationChallenge is one start's code and link proving Target: a
// pending sign-up's address (PendingID names the sign-up), an account's own
// unproven address, or the address a contact change moves to (UserID and
// the account's credential Version).
type verificationChallenge struct {
	Kind      pendingChangeKind `json:"kind"`
	Target    string            `json:"target"`
	UserID    string            `json:"user_id,omitempty"`
	Version   int64             `json:"version,omitempty"`
	PendingID string            `json:"pending_id,omitempty"`
	CodeHash  string            `json:"code_hash"`
	LinkHash  string            `json:"link_hash"`
	handle    string
	expected  []byte
}

const (
	keyVerification         = "verify:challenge:" // +<handle>
	keyVerificationLink     = "verify:link:"      // +<linkHash> -> handle
	keyVerificationFailures = "verify:failures:"  // +<handle>
)

// sendVerification stores a fresh code and link for ch under a new handle,
// beside any other start's, and delivers them with send. A send a quota
// withheld stores nothing and answers the handle as if it went out.
func (s *Engine) sendVerification(ctx context.Context, ch verificationChallenge, send func(code, linkToken string) error) (string, error) {
	if !s.useEphemeralStore() {
		return "", jwt.ErrTokenUnverifiable
	}
	if ch.UserID != "" {
		version, err := s.q.UserCredentialVersion(ctx, ch.UserID)
		if err != nil {
			return "", err
		}
		ch.Version = version.CredentialVersion
	}
	code, link := secret.Digits(6), secret.Token(32)
	ch.handle, ch.CodeHash, ch.LinkHash = newChallengeHandle(), secret.Hash(code), secret.Hash(link)
	ch.Target = normalizePendingTarget(ch.Kind, ch.Target)
	ttl := ch.Kind.defaultTTL()
	if err := s.ephemSetJSON(ctx, keyVerification+ch.handle, ch, ttl); err != nil {
		return "", err
	}
	if err := s.ephemSetString(ctx, keyVerificationLink+ch.LinkHash, ch.handle, ttl); err != nil {
		return "", err
	}
	if err := s.rememberProofRoute(ctx, "verification-link", ch.LinkHash, ttl); err != nil {
		return "", err
	}
	if err := send(code, link); err != nil {
		s.deleteVerification(ctx, ch)
		if withheld(err) {
			return ch.handle, nil
		}
		return "", err
	}
	return ch.handle, nil
}

func (s *Engine) loadVerification(ctx context.Context, handle string) (verificationChallenge, bool, error) {
	var ch verificationChallenge
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return ch, false, nil
	}
	raw, ok, err := s.ephemReadJSON(ctx, keyVerification+handle, &ch)
	ch.handle, ch.expected = handle, raw
	return ch, ok && ch.Kind != "" && ch.Target != "", err
}

// deleteVerification burns ch: its code, link and failure count.
func (s *Engine) deleteVerification(ctx context.Context, ch verificationChallenge) {
	_ = s.ephemDel(ctx, keyVerification+ch.handle)
	_ = s.ephemDel(ctx, keyVerificationFailures+ch.handle)
	if ch.LinkHash != "" {
		_ = s.ephemDel(ctx, keyVerificationLink+ch.LinkHash)
	}
}

// names reports whether identifier is the address ch's code went to.
func (ch verificationChallenge) names(identifier string) bool {
	return ch.Kind.isEmail() == strings.Contains(identifier, "@") && normalizePendingTarget(ch.Kind, identifier) == ch.Target
}

// ConfirmVerification is the shared registration/contact-verification workflow.
// Verification that authenticates a user returns the same MFA/session outcome
// as password and provider login; a contact mutation returns contact_changed.
func (s *Engine) ConfirmVerification(ctx context.Context, in authflow.VerificationInput) (authflow.LoginOutcome, error) {
	if in.Token != "" && in.Code != "" || in.Token == "" && (in.Challenge == "" || in.Code == "") {
		return authflow.LoginOutcome{}, jwt.ErrTokenInvalidClaims
	}
	if !s.useEphemeralStore() {
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	handle := in.Challenge
	if in.Token != "" {
		hash := secret.Hash(in.Token)
		var err error
		if ctx, err = s.proofContext(ctx, "verification-link", hash); err != nil {
			return authflow.LoginOutcome{}, err
		}
		var found bool
		if handle, found, err = s.ephemGetString(ctx, keyVerificationLink+hash); err != nil || !found {
			return authflow.LoginOutcome{}, errOrUnverifiable(err)
		}
	}
	ch, ok, err := s.loadVerification(ctx, handle)
	if err != nil || !ok {
		return authflow.LoginOutcome{}, errOrUnverifiable(err)
	}
	match := in.Identifier == "" || ch.names(in.Identifier)
	if in.Token != "" {
		match = match && secret.Equal(ch.LinkHash, secret.Hash(in.Token))
	} else {
		// A contact change's code is confirmed signed in as its account.
		match = match && secret.Equal(ch.CodeHash, secret.Hash(in.Code)) && (!ch.Kind.isChange() || in.UserID == ch.UserID)
	}
	if !match {
		if in.Token == "" && s.recordFailedAttempt(ctx, keyVerificationFailures+ch.handle, ch.Kind.defaultTTL(), maxChallengeFailures) {
			s.deleteVerification(ctx, ch)
		}
		return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
	}
	var pending pendingChange
	if ch.Kind.isRegister() {
		if pending, ok, err = s.pendingChangeByTarget(ctx, ch.Kind, ch.Target); err != nil {
			return authflow.LoginOutcome{}, err
		}
		if !ok || pending.ID != ch.PendingID {
			s.deleteVerification(ctx, ch)
			return authflow.LoginOutcome{}, jwt.ErrTokenUnverifiable
		}
	}
	if err := s.claimProof(ctx, keyVerification+ch.handle, ch.expected); err != nil {
		return authflow.LoginOutcome{}, err
	}
	s.deleteVerification(ctx, ch)
	var keep *string
	if in.UserID == ch.UserID && in.SessionID != "" {
		keep = &in.SessionID
	}
	var account registeredAccount
	switch {
	case ch.Kind.isRegister():
		if err := s.claimPendingChange(ctx, pending); err != nil {
			return authflow.LoginOutcome{}, err
		}
		input := newAccount{Username: pending.Username, PasswordHash: pending.PasswordHash, HashAlgo: "argon2id"}
		if ch.Kind.isEmail() {
			input.Email = pending.Target
			input.EmailVerified = true // the delivered code/link is the proof
		} else {
			input.PhoneNumber = pending.Target
			input.PhoneVerified = true
		}
		account, err = s.registerAccount(ctx, accountRegistration{User: input, Language: pending.PreferredLanguage, InviteToken: pending.AccountInviteToken, Agreements: pending.Agreements, IP: in.IP, UserAgent: in.UserAgent})
	case ch.Kind.isChange():
		if _, err := s.finalizePendingChange(ctx, pendingChange{Kind: ch.Kind, Target: ch.Target, UserID: ch.UserID, Version: ch.Version}, keep); err != nil {
			return authflow.LoginOutcome{}, err
		}
		return authflow.LoginOutcome{Kind: authflow.LoginContactChanged, UserID: ch.UserID}, nil
	default:
		channel := passwordlessChannelEmail
		if !ch.Kind.isEmail() {
			channel = passwordlessChannelSMS
		}
		var passwordVersion int64
		if passwordVersion, err = s.spendPasswordProof(ctx, in.PasswordProof, ch.UserID); err != nil {
			return authflow.LoginOutcome{}, err
		}
		account, err = s.verifyContactProofWithRecovery(ctx, ch.UserID, ch.Version, channel, ch.Target, true, keep, passwordVersion)
	}
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	method, event := "email", "email_verification"
	if !ch.Kind.isEmail() {
		method, event = "sms", "phone_verification"
	}
	return s.finishFirstFactor(ctx, loginProof{Version: account.Version, AuthenticatedAt: time.Now().UTC(), Created: ch.Kind.isRegister(), Input: loginSessionInput{UserID: account.ID, AuthMethods: []string{method}, Event: event, UserAgent: in.UserAgent, IP: in.IP}})
}

func errOrUnverifiable(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenUnverifiable
}
