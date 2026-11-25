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
	"github.com/jackc/pgx/v5"

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
	Device      authflow.SignInDevice // where the sign-in comes from (Config.SignIn)
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
		u, err = s.loginUserByUsername(ctx, identifier)
		if err != nil || u == nil {
			if err := spendPasswordCheck(ctx, in.Password); err != nil {
				return authflow.LoginOutcome{}, err
			}
			return s.rejectLogin(ctx, in, "", errmodel.ErrInvalidCredentials), nil
		}
	}

	// An account with an unproven contact is one a host operation created
	// (CreateUser, an import, SCIM): every sign-up proves its contact before
	// the account exists. It signs in by password, and stays unproven.

	version, err := s.authenticatePassword(ctx, u, in.Password)
	if errors.Is(err, password.ErrBusy) {
		return authflow.LoginOutcome{}, err
	}
	if err != nil {
		return s.passwordRejected(ctx, in, u.ID, err)
	}
	if out, parked, err := s.restoreGate(ctx, in, u); err != nil || parked {
		return out, err
	}
	out, err := s.finishFirstFactor(ctx, loginProof{Version: version, AuthenticatedAt: time.Now().UTC(), Input: loginSessionInput{UserID: u.ID, AuthMethods: []string{"pwd"}, Event: "password_login", UserAgent: in.UserAgent, IP: in.IP}})
	if errors.Is(err, errmodel.ErrUserBanned) || errors.Is(err, jwt.ErrTokenUnverifiable) {
		return s.rejectLogin(ctx, in, u.ID, loginRejection(err)), nil
	}
	return out, err
}

// loginUserByUsername also finds a deleted account: it keeps its name through
// the recovery window, and a sign-in by that name goes on to restore it.
func (s *Engine) loginUserByUsername(ctx context.Context, username string) (*db.User, error) {
	u, err := s.getUserByUsername(ctx, username)
	if !errors.Is(err, pgx.ErrNoRows) {
		return u, err
	}
	r, err := s.q.UserByUsername(ctx, db.UserByUsernameParams{TenantID: s.tenantKey(ctx), Username: username})
	if err != nil {
		return nil, err
	}
	return &r, nil
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

// pendingResendsPerHour caps the re-sends that signing in with a pending
// sign-up's password triggers for one address, so it cannot flood an inbox.
const pendingResendsPerHour = 6

const keyPendingResend = "pending_change:resend:"

func (s *Engine) pendingResendAllowed(ctx context.Context, kind pendingChangeKind, target string) bool {
	n, err := s.ephemIncr(ctx, keyPendingResend+string(kind)+":"+normalizePendingTarget(kind, target), time.Hour)
	return err == nil && n <= pendingResendsPerHour
}

// spendPasswordCheck costs what one password check costs, so a sign-in that
// finds no account answers in the same time as one that does.
func spendPasswordCheck(ctx context.Context, pw string) error {
	if err := password.Spend(ctx, pw); errors.Is(err, password.ErrBusy) {
		return err
	}
	return nil
}

// passwordRejected answers a wrong password for an account found by email or
// phone. A sign-up attempt on that address left a pending record
// (registerTakenContact); its password answers as a pending sign-up's does
// where no account exists, and the owner is notified again, so the answer
// never shows that an account holds the address.
func (s *Engine) passwordRejected(ctx context.Context, in authflow.PasswordLoginInput, userID string, err error) (authflow.LoginOutcome, error) {
	reason := loginRejection(err)
	identifier := strings.TrimSpace(in.Identifier)
	kind := kindRegisterEmail
	if !strings.Contains(identifier, "@") {
		kind = kindRegisterPhone
	}
	if !errors.Is(reason, errmodel.ErrInvalidCredentials) || !s.registrationVerificationRequired() ||
		!strings.Contains(identifier, "@") && !strings.HasPrefix(identifier, "+") {
		return s.rejectLogin(ctx, in, userID, reason), nil
	}
	pending, ok, perr := s.pendingChangeByTarget(ctx, kind, identifier)
	if perr != nil || !ok {
		return s.rejectLogin(ctx, in, userID, reason), nil
	}
	valid, verr := password.VerifyArgon2id(ctx, pending.PasswordHash, in.Password)
	if errors.Is(verr, password.ErrBusy) {
		return authflow.LoginOutcome{}, verr
	}
	if verr != nil || !valid {
		return s.rejectLogin(ctx, in, userID, reason), nil
	}
	s.loginFailed(ctx, in, userID, reason.Error())
	if s.pendingResendAllowed(ctx, kind, pending.Target) {
		if err := s.renewTakenRegistration(ctx, kind, pending.Target); err != nil {
			return authflow.LoginOutcome{}, err
		}
		if err := s.notifyAccountExists(ctx, notifyChannel(kind), pending.Target); err != nil {
			return authflow.LoginOutcome{}, err
		}
	}
	channel := "email"
	if kind == kindRegisterPhone {
		channel = "phone"
	}
	return authflow.LoginOutcome{Kind: authflow.LoginVerificationRequired, Verification: &authflow.VerificationRequired{Identifier: identifier, Channel: channel, Challenge: newChallengeHandle()}}, nil
}

// recoverPendingLogin resends the same pending signup after checking its password.
func (s *Engine) recoverPendingLogin(ctx context.Context, in authflow.PasswordLoginInput, kind pendingChangeKind, identifier string) (authflow.LoginOutcome, error) {
	pending, ok, err := s.pendingChangeByTarget(ctx, kind, identifier)
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	// One check here stands for the account's; a pending record adds its own,
	// as a placeholder does beside an account (passwordRejected).
	if err := spendPasswordCheck(ctx, in.Password); err != nil {
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
	challenge := newChallengeHandle()
	if s.pendingResendAllowed(ctx, kind, identifier) {
		if challenge, _, err = s.resendRegistration(ctx, identifier); err != nil {
			return authflow.LoginOutcome{}, err
		}
	}
	channel := "email"
	if kind == kindRegisterPhone {
		channel = "phone"
	}
	return authflow.LoginOutcome{Kind: authflow.LoginVerificationRequired, Verification: &authflow.VerificationRequired{Identifier: identifier, Channel: channel, Challenge: challenge}}, nil
}

// verificationRequired parks a login that proved userID's password at the code
// sent to identifier for challenge, with the password proof its confirmation
// may present for as long as the code lives.
func (s *Engine) verificationRequired(ctx context.Context, userID, identifier, channel, challenge string, ttl time.Duration) (authflow.LoginOutcome, bool, error) {
	proof, err := s.issuePasswordProof(ctx, userID, ttl)
	if err != nil {
		return authflow.LoginOutcome{}, true, err
	}
	return authflow.LoginOutcome{Kind: authflow.LoginVerificationRequired, UserID: userID,
		Verification: &authflow.VerificationRequired{Identifier: identifier, Channel: channel, Challenge: challenge, PasswordProof: proof}}, true, nil
}
