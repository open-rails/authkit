package embedded

// Password login as ONE engine decision (ak#318): identifier resolution,
// pending-registration recovery, the verification gate, the credential check,
// the liveness gate, the 2FA challenge and session issue all live here and
// come back as a closed LoginOutcome. The transport decodes, rate-limits,
// calls, and switches on Kind — it re-derives no policy.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/password"
)

// stageErr prefixes an engine failure with the stage it happened in, for the
// transport's log; errors.Is/As see through it to the wrapped cause.
func stageErr(stage string, err error) error { return fmt.Errorf("%s: %w", stage, err) }

// IssuedSession is a freshly established refresh session plus its paired
// access token.
type IssuedSession struct {
	SessionID       string
	RefreshToken    string
	AccessToken     string
	AccessExpiresAt time.Time
}

// TokenSet is the wire shape of an IssuedSession.
func (s IssuedSession) TokenSet() authkit.TokenSet {
	return authkit.NewTokenSet(s.AccessToken, s.RefreshToken, s.AccessExpiresAt)
}

// LoginSessionInput describes the session a completed authentication earns.
type LoginSessionInput struct {
	UserID      string
	AuthMethods []string       // how the session was established, e.g. {"pwd"}
	Event       string         // session-created audit event, e.g. "password_login"
	Extra       map[string]any // extra access-token claims
	UserAgent   string
	IP          string
}

// IssueLoginSession creates the refresh session, mints its access token and
// writes the session-created audit event — the shared tail of every login.
// The liveness and MFA gates fire exactly as IssueAuthenticatedSession does
// (ErrUserBanned, ErrTwoFAEnrollmentRequired).
func (s *engine) IssueLoginSession(ctx context.Context, in LoginSessionInput) (IssuedSession, error) {
	sid, rt, access, exp, _, err := s.IssueAuthenticatedSession(ctx, in.UserID, in.UserAgent, net.ParseIP(in.IP), in.AuthMethods, in.Extra)
	if err != nil {
		return IssuedSession{}, err
	}
	s.LogSessionCreated(ctx, in.UserID, in.Event, sid, nullable(in.IP), nullable(in.UserAgent))
	return IssuedSession{SessionID: sid, RefreshToken: rt, AccessToken: access, AccessExpiresAt: exp}, nil
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
	// LoginRejected: no session; Reason says why (ErrInvalidCredentials,
	// ErrUserBanned, ErrPasswordResetRequired).
	LoginRejected LoginOutcomeKind = "rejected"
)

// VerificationRequired names the contact channel a login is parked on.
type VerificationRequired struct {
	Identifier string
	Channel    string // "email" | "phone"
}

// TwoFactorChallenge is the second-factor step a password login opened.
type TwoFactorChallenge struct {
	Method      string
	Destination string // where the code went (email/phone), unmasked
	Challenge   string
	Factor      TwoFactorFactor
	Factors     []TwoFactorFactor
}

// LoginOutcome is the result of a password login. Exactly one of Session,
// Verification and Challenge is set, per Kind; Reason is set for LoginRejected.
type LoginOutcome struct {
	Enrollment     *authkit.TokenSet
	AllowedMethods []string
	ReturnTo       string
	Created        bool
	Kind           LoginOutcomeKind
	UserID         string
	Reason         error
	Session        *IssuedSession
	Verification   *VerificationRequired
	Challenge      *TwoFactorChallenge
}

// PasswordLoginInput is a password login attempt. Identifier is an email
// (contains "@"), an E.164 phone ("+…") or a username.
type PasswordLoginInput struct {
	Identifier string
	Password   string
	UserAgent  string
	IP         string
}

// PasswordLogin runs the whole password-login decision tree. It returns an
// error only when the engine itself failed (a send, the challenge store, the
// session insert — each prefixed with its stage and, for sends, the
// delivery sentinel); every policy result is a LoginOutcome.
func (s *engine) PasswordLogin(ctx context.Context, in PasswordLoginInput) (LoginOutcome, error) {
	identifier := strings.TrimSpace(in.Identifier)
	if identifier == "" || in.Password == "" {
		return s.rejectLogin(ctx, in, "", ErrInvalidCredentials), nil
	}
	requiresVerification := s.RegistrationVerificationRequired()

	var (
		u   *User
		err error
	)
	switch {
	case strings.Contains(identifier, "@"):
		u, err = s.getUserByEmail(ctx, identifier)
		if err != nil || u == nil {
			// No account: a pending (unverified) email registration whose password
			// matches is re-sent.
			return s.recoverPendingLogin(ctx, in, KindRegisterEmail, identifier)
		}
	case strings.HasPrefix(identifier, "+"):
		u, err = s.getUserByPhone(ctx, identifier)
		if err != nil || u == nil {
			return s.recoverPendingLogin(ctx, in, KindRegisterPhone, identifier)
		}
	default:
		u, err = s.getUserByUsername(ctx, identifier)
		if err != nil || u == nil {
			return s.rejectLogin(ctx, in, "", ErrInvalidCredentials), nil
		}
	}

	// Verify the password BEFORE sending any OTP so an unauthenticated caller
	// can neither trigger sends nor enumerate accounts.
	if requiresVerification {
		if out, parked, err := s.verificationGate(ctx, in, u); err != nil || parked {
			return out, err
		}
	}

	version, err := s.authenticatePassword(ctx, u, in.Password)
	if err != nil {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}
	out, err := s.finishFirstFactor(ctx, loginProof{Version: version, AuthenticatedAt: time.Now().UTC(), Input: LoginSessionInput{UserID: u.ID, AuthMethods: []string{"pwd"}, Event: "password_login", UserAgent: in.UserAgent, IP: in.IP}})
	if errors.Is(err, ErrUserBanned) || errors.Is(err, jwt.ErrTokenUnverifiable) {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}
	return out, err
}

// Password-login errors shared with the transport.
var (
	ErrInvalidCredentials          = authkit.ErrInvalidCredentials
	ErrEmailVerificationSendFailed = authkit.ErrEmailVerificationSendFailed
	ErrPhoneVerificationSendFailed = authkit.ErrPhoneVerificationSendFailed
)

// loginRejection maps a credential/liveness failure to its rejection reason.
func loginRejection(err error) error {
	switch {
	case errors.Is(err, ErrUserBanned):
		return ErrUserBanned
	case errors.Is(err, ErrPasswordResetRequired):
		return ErrPasswordResetRequired
	default:
		return ErrInvalidCredentials
	}
}

func (s *engine) rejectLogin(ctx context.Context, in PasswordLoginInput, userID string, reason error) LoginOutcome {
	s.loginFailed(ctx, in, userID, reason.Error())
	return LoginOutcome{Kind: LoginRejected, UserID: userID, Reason: reason}
}

func (s *engine) loginFailed(ctx context.Context, in PasswordLoginInput, userID, reason string) {
	s.LogSessionFailed(ctx, userID, "", &reason, nullable(in.IP), nullable(in.UserAgent))
}

// recoverPendingLogin resends the same pending signup after checking its password.
func (s *engine) recoverPendingLogin(ctx context.Context, in PasswordLoginInput, kind PendingChangeKind, identifier string) (LoginOutcome, error) {
	pending, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil {
		return LoginOutcome{}, err
	}
	if !ok {
		return s.rejectLogin(ctx, in, "", ErrInvalidCredentials), nil
	}
	valid, err := password.VerifyArgon2id(pending.PasswordHash, in.Password)
	if err != nil || !valid {
		return s.rejectLogin(ctx, in, "", ErrInvalidCredentials), nil
	}
	if _, err := s.ResendRegistration(ctx, identifier); err != nil {
		return LoginOutcome{}, err
	}
	channel := "email"
	if kind == KindRegisterPhone {
		channel = "phone"
	}
	return LoginOutcome{Kind: LoginVerificationRequired, Verification: &VerificationRequired{Identifier: identifier, Channel: channel}}, nil
}

// verificationGate parks an unverified account: the password must verify
// first (no OTP for the unauthenticated), then a fresh code goes out over the
// unverified channel and the login ends in LoginVerificationRequired.
func (s *engine) verificationGate(ctx context.Context, in PasswordLoginInput, u *User) (LoginOutcome, bool, error) {
	needsEmail := !u.EmailVerified && u.Email != nil
	needsPhone := !u.PhoneVerified && u.PhoneNumber != nil
	if !needsEmail && !needsPhone {
		return LoginOutcome{}, false, nil
	}
	if err := s.CheckUserPassword(ctx, u.ID, in.Password); err != nil {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), true, nil
	}
	if needsEmail && s.HasEmailSender() {
		if err := s.RequestEmailVerification(ctx, *u.Email, 0); err != nil {
			return LoginOutcome{}, true, stageErr("send_email_verification", fmt.Errorf("%w: %w", ErrEmailVerificationSendFailed, err))
		}
		s.loginFailed(ctx, in, u.ID, "email_not_verified")
		return LoginOutcome{Kind: LoginVerificationRequired, UserID: u.ID, Verification: &VerificationRequired{Identifier: *u.Email, Channel: "email"}}, true, nil
	}
	if needsPhone && s.SMSAvailable() {
		if err := s.SendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, 0); err != nil {
			return LoginOutcome{}, true, stageErr("send_phone_verification", fmt.Errorf("%w: %w", ErrPhoneVerificationSendFailed, err))
		}
		s.loginFailed(ctx, in, u.ID, "phone_not_verified")
		return LoginOutcome{Kind: LoginVerificationRequired, UserID: u.ID, Verification: &VerificationRequired{Identifier: *u.PhoneNumber, Channel: "phone"}}, true, nil
	}
	return LoginOutcome{}, false, nil
}
