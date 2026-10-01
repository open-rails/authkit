package engine

// Password login as ONE engine decision (ak#318): identifier resolution,
// pending-registration recovery, the verification gate, the credential check,
// the account gate, the 2FA challenge and session issue all live here and
// come back as a closed LoginOutcome. The transport decodes, rate-limits,
// calls, and switches on Kind — it re-derives no policy.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/password"
)

// stageErr prefixes an engine failure with the stage it happened in, for the
// transport's log; errors.Is/As see through it to the wrapped cause.
func stageErr(stage string, err error) error { return fmt.Errorf("%s: %w", stage, err) }

// LoginSessionInput describes the session a completed authentication earns.
type loginSessionInput struct {
	UserID      string
	AuthMethods []string       // how the session was established, e.g. {"pwd"}
	Event       string         // session-created audit event, e.g. "password_login"
	Extra       map[string]any // extra access-token claims
	UserAgent   string
	IP          string
}

// PasswordLogin runs the whole password-login decision tree. It returns an
// error only when the engine itself failed (a send, the challenge store, the
// session insert — each prefixed with its stage and, for sends, the
// delivery sentinel); every policy result is a LoginOutcome.
func (s *Engine) PasswordLogin(ctx context.Context, in authflow.PasswordLoginInput) (authflow.LoginOutcome, error) {
	identifier := strings.TrimSpace(in.Identifier)
	if identifier == "" || in.Password == "" {
		return s.rejectLogin(ctx, in, "", errmodel.ErrInvalidCredentials), nil
	}
	requiresVerification := s.registrationVerificationRequired()

	var (
		u   *db.User
		err error
	)
	switch {
	case strings.Contains(identifier, "@"):
		u, err = s.getUserByEmail(ctx, identifier)
		if err != nil || u == nil {
			// No account: a pending (unverified) email registration whose password
			// matches is re-sent.
			return s.recoverPendingLogin(ctx, in, kindRegisterEmail, identifier)
		}
	case strings.HasPrefix(identifier, "+"):
		u, err = s.getUserByPhone(ctx, identifier)
		if err != nil || u == nil {
			return s.recoverPendingLogin(ctx, in, kindRegisterPhone, identifier)
		}
	default:
		u, err = s.getUserByUsername(ctx, identifier)
		if err != nil || u == nil {
			return s.rejectLogin(ctx, in, "", errmodel.ErrInvalidCredentials), nil
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
	if errors.Is(err, password.ErrBusy) {
		return authflow.LoginOutcome{}, err
	}
	if err != nil {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}
	out, err := s.finishFirstFactor(ctx, loginProof{Version: version, AuthenticatedAt: time.Now().UTC(), Input: loginSessionInput{UserID: u.ID, AuthMethods: []string{"pwd"}, Event: "password_login", UserAgent: in.UserAgent, IP: in.IP}})
	if errors.Is(err, errmodel.ErrUserBanned) || errors.Is(err, jwt.ErrTokenUnverifiable) {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}
	return out, err
}

// loginRejection maps a credential or account-gate failure to its rejection reason.
func loginRejection(err error) error {
	switch {
	case errors.Is(err, errmodel.ErrUserBanned):
		return errmodel.ErrUserBanned
	case errors.Is(err, errmodel.ErrPasswordResetRequired):
		return errmodel.ErrPasswordResetRequired
	default:
		return errmodel.ErrInvalidCredentials
	}
}

func (s *Engine) rejectLogin(ctx context.Context, in authflow.PasswordLoginInput, userID string, reason error) authflow.LoginOutcome {
	s.loginFailed(ctx, in, userID, reason.Error())
	return authflow.LoginOutcome{Kind: authflow.LoginRejected, UserID: userID, Reason: reason}
}

func (s *Engine) loginFailed(ctx context.Context, in authflow.PasswordLoginInput, userID, reason string) {
	s.LogSessionFailed(ctx, userID, "", &reason, nullable(in.IP), nullable(in.UserAgent))
}

// recoverPendingLogin resends the same pending signup after checking its password.
func (s *Engine) recoverPendingLogin(ctx context.Context, in authflow.PasswordLoginInput, kind pendingChangeKind, identifier string) (authflow.LoginOutcome, error) {
	pending, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	if !ok {
		return s.rejectLogin(ctx, in, "", errmodel.ErrInvalidCredentials), nil
	}
	valid, err := password.VerifyArgon2id(ctx, pending.PasswordHash, in.Password)
	if errors.Is(err, password.ErrBusy) {
		return authflow.LoginOutcome{}, err
	}
	if err != nil || !valid {
		return s.rejectLogin(ctx, in, "", errmodel.ErrInvalidCredentials), nil
	}
	if _, err := s.resendRegistration(ctx, identifier); err != nil {
		return authflow.LoginOutcome{}, err
	}
	channel := "email"
	if kind == kindRegisterPhone {
		channel = "phone"
	}
	return authflow.LoginOutcome{Kind: authflow.LoginVerificationRequired, Verification: &authflow.VerificationRequired{Identifier: identifier, Channel: channel}}, nil
}

// verificationGate parks an unverified account: the password must verify
// first (no OTP for the unauthenticated), then a fresh code goes out over the
// unverified channel and the login ends in LoginVerificationRequired with a
// password proof.
func (s *Engine) verificationGate(ctx context.Context, in authflow.PasswordLoginInput, u *db.User) (authflow.LoginOutcome, bool, error) {
	needsEmail := !u.EmailVerified && u.Email != nil
	needsPhone := !u.PhoneVerified && u.PhoneNumber != nil
	if !needsEmail && !needsPhone {
		return authflow.LoginOutcome{}, false, nil
	}
	if err := s.CheckUserPassword(ctx, u.ID, in.Password); errors.Is(err, password.ErrBusy) {
		return authflow.LoginOutcome{}, true, err
	} else if err != nil {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), true, nil
	}
	if needsEmail && s.EmailAvailable() {
		if err := s.RequestEmailVerification(ctx, *u.Email, 0); err != nil {
			return authflow.LoginOutcome{}, true, stageErr("send_email_verification", fmt.Errorf("%w: %w", errmodel.ErrEmailVerificationSendFailed, err))
		}
		s.loginFailed(ctx, in, u.ID, "email_not_verified")
		return s.verificationRequired(ctx, u.ID, *u.Email, "email", defaultEmailVerificationTTL)
	}
	if needsPhone && s.SMSAvailable() {
		if err := s.sendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, 0); err != nil {
			return authflow.LoginOutcome{}, true, stageErr("send_phone_verification", fmt.Errorf("%w: %w", errmodel.ErrPhoneVerificationSendFailed, err))
		}
		s.loginFailed(ctx, in, u.ID, "phone_not_verified")
		return s.verificationRequired(ctx, u.ID, *u.PhoneNumber, "phone", defaultPhoneVerificationTTL)
	}
	return authflow.LoginOutcome{}, false, nil
}

// verificationRequired parks a login that proved userID's password at the code
// sent to identifier, with the password proof its confirmation may present
// for as long as the code lives.
func (s *Engine) verificationRequired(ctx context.Context, userID, identifier, channel string, ttl time.Duration) (authflow.LoginOutcome, bool, error) {
	proof, err := s.issuePasswordProof(ctx, userID, ttl)
	if err != nil {
		return authflow.LoginOutcome{}, true, err
	}
	return authflow.LoginOutcome{Kind: authflow.LoginVerificationRequired, UserID: userID,
		Verification: &authflow.VerificationRequired{Identifier: identifier, Channel: channel, PasswordProof: proof}}, true, nil
}
