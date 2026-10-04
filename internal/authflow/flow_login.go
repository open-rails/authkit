package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

// IssuedSession is a freshly established refresh session plus its paired
// access token.
type IssuedSession struct {
	SessionID       string
	RefreshToken    string
	AccessToken     string
	AccessExpiresAt time.Time
}

// TokenSet is the wire shape of an IssuedSession.
func (s IssuedSession) TokenSet() iam.TokenSet {
	return NewTokenSet(s.AccessToken, s.RefreshToken, s.AccessExpiresAt)
}

// NewTokenSet builds a Bearer TokenSet whose expires_in is derived from exp;
// an empty refresh token is none.
func NewTokenSet(access, refresh string, exp time.Time) iam.TokenSet {
	t := iam.TokenSet{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds())}
	if refresh != "" {
		t.RefreshToken = &refresh
	}
	return t
}

// LoginOutcomeKind is the closed set of ways a login attempt ends.
type LoginOutcomeKind string

const (
	LoginProviderLinked LoginOutcomeKind = "provider_linked"
	LoginContactChanged LoginOutcomeKind = "contact_changed"
	// LoginSessionIssued: the caller is signed in; Session carries the tokens.
	LoginSessionIssued LoginOutcomeKind = "session_issued"
	// LoginVerificationRequired: the identifier still needs verifying; a fresh
	// code was just sent to Verification.Identifier over Verification.Channel.
	LoginVerificationRequired LoginOutcomeKind = "verification_required"
	// LoginTwoFactorRequired: the password verified; a second factor is now
	// pending (Challenge carries the issued challenge and the factor menu).
	LoginTwoFactorRequired LoginOutcomeKind = "2fa_required"
	// LoginTwoFAEnrollmentRequired: the password verified but the deployment
	// requires a second factor the user has not enrolled yet.
	LoginTwoFAEnrollmentRequired LoginOutcomeKind = "2fa_enrollment_required"
	// LoginDeviceVerificationRequired: a new device past the account's limit;
	// Device carries the code's challenge.
	LoginDeviceVerificationRequired LoginOutcomeKind = "device_verification_required"
	// LoginRejected: no session; Reason says why (ErrInvalidCredentials,
	// ErrUserBanned, ErrPasswordResetRequired).
	LoginRejected LoginOutcomeKind = "rejected"
)

// VerificationRequired names the contact channel a login is parked on.
// PasswordProof, when the login proved the account's password, is the
// single-use token that lets the confirmation keep it (VerificationInput).
type VerificationRequired struct {
	Identifier    string
	Channel       string // "email" | "phone"
	PasswordProof string
}

// TwoFactorChallenge is the second-factor step a password login opened.
type TwoFactorChallenge struct {
	Method      string
	Destination string // where the code went (email/phone), unmasked
	Challenge   string
	Factor      MFAFactor
	Factors     []MFAFactor
}

// LoginOutcome is the result of a password login. Exactly one of Session,
// Verification and Challenge is set, per Kind; Reason is set for LoginRejected.
type LoginOutcome struct {
	Recovery       *AccountRecoveryConfirmation
	Enrollment     *iam.TokenSet
	AllowedMethods []iam.TwoFactorMethod
	ReturnTo       string
	Created        bool
	Kind           LoginOutcomeKind
	UserID         string
	Reason         error
	Session        *IssuedSession
	Verification   *VerificationRequired
	Challenge      *TwoFactorChallenge
	Device         *DeviceChallenge
}

const LoginRecoveryRequired LoginOutcomeKind = "account_recovery_required"

// PasswordLoginInput is a password login attempt. Identifier is an email
// (contains "@"), an E.164 phone ("+…") or a username.
type PasswordLoginInput struct {
	Identifier string
	Password   string
	UserAgent  string
	IP         string
}
