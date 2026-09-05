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

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/password"
)

// FlowError tags an engine failure with the stage it happened in, so a
// transport can log where a flow broke without re-deriving the flow.
// errors.Is / errors.As see through it to the wrapped cause.
type FlowError struct {
	Stage string
	Err   error
}

func (e *FlowError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *FlowError) Unwrap() error { return e.Err }

func stageErr(stage string, err error) error { return &FlowError{Stage: stage, Err: err} }

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
func (s *Client) IssueLoginSession(ctx context.Context, in LoginSessionInput) (IssuedSession, error) {
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
	Kind         LoginOutcomeKind
	UserID       string
	Reason       error
	Session      *IssuedSession
	Verification *VerificationRequired
	Challenge    *TwoFactorChallenge
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
// session insert — each tagged with its FlowError stage and, for sends, the
// delivery sentinel); every policy result is a LoginOutcome.
func (s *Client) PasswordLogin(ctx context.Context, in PasswordLoginInput) (LoginOutcome, error) {
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
			// matches is re-sent, or completed when verification is optional.
			out, recovered := s.recoverPendingEmailLogin(ctx, in, identifier, requiresVerification)
			if !recovered {
				return out.LoginOutcome, nil
			}
			u = out.user
		}
	case strings.HasPrefix(identifier, "+"):
		u, err = s.getUserByPhone(ctx, identifier)
		if err != nil || u == nil {
			out, recovered := s.recoverPendingPhoneLogin(ctx, in, identifier, requiresVerification)
			if !recovered {
				return out.LoginOutcome, nil
			}
			u = out.user
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

	if err := s.authenticatePassword(ctx, u, in.Password); err != nil {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}

	if settings, err := s.Get2FASettings(ctx, u.ID); err == nil && settings != nil && settings.Enabled && s.TwoFactorEnabled() {
		destination, method, factor, err := s.Require2FAForLoginFactor(ctx, u.ID, "")
		if err != nil {
			return LoginOutcome{}, stageErr("send_2fa_code", fmt.Errorf("%w: %w", ErrTwoFASendFailed, err))
		}
		challenge, err := s.Create2FAChallenge(ctx, u.ID)
		if err != nil {
			return LoginOutcome{}, stageErr("create_2fa_challenge", fmt.Errorf("%w: %w", ErrTwoFAChallengeFailed, err))
		}
		return LoginOutcome{Kind: LoginTwoFactorRequired, UserID: u.ID, Challenge: &TwoFactorChallenge{
			Method: method, Destination: destination, Challenge: challenge, Factor: factor, Factors: settings.Factors,
		}}, nil
	}

	session, err := s.IssueLoginSession(ctx, LoginSessionInput{UserID: u.ID, AuthMethods: []string{"pwd"}, Event: "password_login", UserAgent: in.UserAgent, IP: in.IP})
	if err != nil {
		if errors.Is(err, ErrTwoFAEnrollmentRequired) {
			return LoginOutcome{Kind: LoginTwoFAEnrollmentRequired, UserID: u.ID}, nil
		}
		if errors.Is(err, ErrUserBanned) {
			return s.rejectLogin(ctx, in, u.ID, ErrUserBanned), nil
		}
		return LoginOutcome{}, stageErr("issue_session", fmt.Errorf("%w: %w", ErrSessionIssueFailed, err))
	}
	return LoginOutcome{Kind: LoginSessionIssued, UserID: u.ID, Session: &session}, nil
}

// ErrTwoFASendFailed etc. are the flow sentinels a transport maps (root package).
var (
	ErrInvalidCredentials          = authkit.ErrInvalidCredentials
	ErrTwoFASendFailed             = authkit.ErrTwoFASendFailed
	ErrTwoFAChallengeFailed        = authkit.ErrTwoFAChallengeFailed
	ErrSessionIssueFailed          = authkit.ErrSessionIssueFailed
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

func (s *Client) rejectLogin(ctx context.Context, in PasswordLoginInput, userID string, reason error) LoginOutcome {
	s.loginFailed(ctx, in, userID, reason.Error())
	return LoginOutcome{Kind: LoginRejected, UserID: userID, Reason: reason}
}

func (s *Client) loginFailed(ctx context.Context, in PasswordLoginInput, userID, reason string) {
	s.LogSessionFailed(ctx, userID, "", &reason, nullable(in.IP), nullable(in.UserAgent))
}

// pendingRecovery is the internal result of a pending-registration recovery:
// either a resolved user to continue with, or the outcome to return.
type pendingRecovery struct {
	LoginOutcome
	user *User
}

// recoverPendingEmailLogin handles a login against an email that has no
// account yet but a pending registration whose password matches: the pending
// registration is re-created (which re-sends the code, or — when verification
// is not required — creates the account outright).
func (s *Client) recoverPendingEmailLogin(ctx context.Context, in PasswordLoginInput, email string, requiresVerification bool) (pendingRecovery, bool) {
	pending, err := s.GetPendingRegistrationByEmail(ctx, email)
	if err != nil || pending == nil || !s.VerifyPendingPassword(ctx, email, in.Password) {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	if _, err := s.CreatePendingRegistrationWithLanguage(ctx, email, pending.Username, pending.PasswordHash, 0, pending.PreferredLanguage); err != nil {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	if requiresVerification {
		return pendingRecovery{LoginOutcome: LoginOutcome{Kind: LoginVerificationRequired, Verification: &VerificationRequired{Identifier: email, Channel: "email"}}}, false
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	return pendingRecovery{user: u}, true
}

func (s *Client) recoverPendingPhoneLogin(ctx context.Context, in PasswordLoginInput, phone string, requiresVerification bool) (pendingRecovery, bool) {
	pending, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone)
	if err != nil || pending == nil {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	if ok, verr := password.VerifyArgon2id(pending.PasswordHash, in.Password); verr != nil || !ok {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	if _, err := s.CreatePendingPhoneRegistrationWithLanguage(ctx, phone, pending.Username, pending.PasswordHash, pending.PreferredLanguage); err != nil {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	if requiresVerification {
		return pendingRecovery{LoginOutcome: LoginOutcome{Kind: LoginVerificationRequired, Verification: &VerificationRequired{Identifier: phone, Channel: "phone"}}}, false
	}
	u, err := s.getUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return pendingRecovery{LoginOutcome: s.rejectLogin(ctx, in, "", ErrInvalidCredentials)}, false
	}
	return pendingRecovery{user: u}, true
}

// verificationCutoff: accounts created before it predate verification and are
// never parked on it.
var verificationCutoff = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

// verificationGate parks an unverified account: the password must verify
// first (no OTP for the unauthenticated), then a fresh code goes out over the
// unverified channel and the login ends in LoginVerificationRequired.
func (s *Client) verificationGate(ctx context.Context, in PasswordLoginInput, u *User) (LoginOutcome, bool, error) {
	recent := u.CreatedAt.After(verificationCutoff)
	needsEmail := recent && !u.EmailVerified && u.Email != nil
	needsPhone := recent && !u.PhoneVerified && u.PhoneNumber != nil
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
