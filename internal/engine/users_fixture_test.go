package engine

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/open-rails/authkit/iam"
)

// Account and session setup shortcuts for engine tests: the public actor
// operations with operator authority, and trusted session issuance that
// production reaches only through the login flows.

// markEmailVerified sets the flag without the proof transition: a setup
// shortcut for accounts whose credentials the test itself created.
func (s *Engine) markEmailVerified(ctx context.Context, id string) error {
	_, err := s.pg.Exec(ctx, `UPDATE users SET email_verified=true WHERE id=$1::uuid`, id)
	return err
}

func (s *Engine) adminSetPassword(ctx context.Context, id, pw string) error {
	_, err := s.UpdateUser(ctx, iam.OperatorActor(), id, iam.UserUpdate{Password: &pw})
	return err
}

func (s *Engine) upsertPasswordHash(ctx context.Context, id, hash, algo string) error {
	_, err := s.UpdateUser(ctx, iam.OperatorActor(), id, iam.UserUpdate{PasswordHash: &iam.PasswordHash{Hash: hash, Algo: algo}})
	return err
}

func (s *Engine) softDelete(ctx context.Context, id string) error {
	return itemErr(s.DeleteUsers(ctx, iam.OperatorActor(), []string{id}))
}

func (s *Engine) mintTestAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error) {
	return s.mintAccessToken(ctx, userID, extra, s.cfg.Token.AccessTokenDuration)
}

// updateImportedUser applies an import row to an existing account, as
// bootstrap does.
func (s *Engine) updateImportedUser(ctx context.Context, id string, input newAccount) (*userRecord, error) {
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.lockAuthority(ctx, tx); err != nil {
		return nil, err
	}
	u, err := s.updateImportedUserTx(ctx, tx, id, input)
	if err != nil {
		return nil, err
	}
	return u, tx.Commit(ctx)
}

// issueRefreshSession creates a session row and returns a new refresh token string.
func (s *Engine) issueRefreshSession(ctx context.Context, userID, userAgent string, ip net.IP) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	return s.issueRefreshSessionWithAuthMethods(ctx, userID, userAgent, ip, []string{"pwd"})
}

// issueRefreshSessionWithAuthMethods creates a refresh session and records the
// authentication methods that established it. Callers minting a session after
// MFA should pass e.g. []string{"pwd", "otp", "mfa"}.
func (s *Engine) issueRefreshSessionWithAuthMethods(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string) (sessionID, refreshToken string, expiresAt *time.Time, err error) {
	if s.pg == nil {
		return "", "", nil, errors.New("postgres not configured")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	if _, err := s.lockLoginAccount(ctx, q, userID, 0); err != nil {
		return "", "", nil, err
	}
	settings, settingsErr := s.get2FASettings(ctx, q, userID)
	status, statusErr := s.mfaStatusWith(settings, settingsErr)
	if err := s.requireSessionMFAStateOn(ctx, tx, userID, authMethods, status, statusErr); err != nil {
		return "", "", nil, err
	}
	sid, rt, exp, evicted, err := s.insertRefreshSessionTx(ctx, q, userID, userAgent, ip, authMethods)
	if err != nil {
		return "", "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", nil, err
	}
	s.logSessionEvictions(ctx, userID, evicted)
	return sid, rt, exp, nil
}

// issueAuthenticatedSession issues a session for a trusted, already-authenticated
// caller. Interactive login flows additionally check their captured proof version
// before using the same transaction-owned issuance helper.
func (s *Engine) issueAuthenticatedSession(ctx context.Context, userID, userAgent string, ip net.IP, authMethods []string, extra map[string]any) (string, string, string, time.Time, *time.Time, error) {
	if s.pg == nil {
		return "", "", "", time.Time{}, nil, errors.New("postgres not configured")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	defer tx.Rollback(ctx)
	q := s.qtx(tx)
	u, err := s.lockLoginAccount(ctx, q, userID, 0)
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	settings, settingsErr := s.get2FASettings(ctx, q, userID)
	mfa, mfaErr := s.mfaStatusWith(settings, settingsErr)
	if err := s.requireSessionMFAStateOn(ctx, tx, userID, authMethods, mfa, mfaErr); err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	address := ""
	if ip != nil {
		address = ip.String()
	}
	session, exp, evicted, err := s.issueLoginSessionTx(ctx, q, u, mfa, loginSessionInput{UserID: userID, UserAgent: userAgent, IP: address, AuthMethods: authMethods, Extra: extra})
	if err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", time.Time{}, nil, err
	}
	s.logSessionEvictions(ctx, userID, evicted)
	return session.SessionID, session.RefreshToken, session.AccessToken, session.AccessExpiresAt, exp, nil
}
