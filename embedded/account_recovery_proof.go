package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
)

// AccountRecoveryConfirmation is an opaque proof, never an access token or
// session. Confirmation restores this deletion generation without signing in.
type AccountRecoveryConfirmation struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	PurgeAt   time.Time `json:"purge_at"`
}

type accountRecoveryProof struct {
	AuthMethods []string  `json:"auth_methods"`
	UserID      string    `json:"user_id"`
	Generation  string    `json:"generation"`
	Issuer      string    `json:"issuer"`
	Version     int64     `json:"version"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *engine) ensureLoginProofAccess(ctx context.Context, user *User) error {
	if user == nil {
		return jwt.ErrTokenUnverifiable
	}
	copy := *user
	copy.DeletedAt = nil
	return s.ensureUserAccess(ctx, &copy)
}

// Called with the account row locked; a normal in-flight proof cannot cross a
// credential-version change or switch to a later deletion cycle.
func (s *engine) bindRecoveryGeneration(ctx context.Context, tx pgx.Tx, user *User, proof *loginProof) error {
	if user.DeletedAt == nil {
		if proof.DeletionID != "" {
			return jwt.ErrTokenUnverifiable
		}
		return nil
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM account_deletions WHERE user_id=$1::uuid AND state='deleted' AND deleted_at=$2 AND purge_at>statement_timestamp()`, user.ID, user.DeletedAt).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.E(authkit.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	if proof.DeletionID != "" && proof.DeletionID != id {
		return jwt.ErrTokenUnverifiable
	}
	proof.DeletionID = id
	return nil
}

func (s *engine) finishRecoveryProof(ctx context.Context, tx pgx.Tx, proof loginProof) (LoginOutcome, error) {
	var now, purgeAt time.Time
	if err := tx.QueryRow(ctx, `SELECT statement_timestamp(),purge_at FROM account_deletions WHERE id=$1::uuid AND user_id=$2::uuid AND state='deleted' AND purge_at>statement_timestamp()`, proof.DeletionID, proof.Input.UserID).Scan(&now, &purgeAt); err != nil {
		return LoginOutcome{}, err
	}
	expires := now.Add(10 * time.Minute)
	if purgeAt.Before(expires) {
		expires = purgeAt
	}
	token := RandB64(32)
	record := accountRecoveryProof{UserID: proof.Input.UserID, Generation: proof.DeletionID, Issuer: s.cfg.Token.Issuer, Version: proof.Version, ExpiresAt: expires, AuthMethods: proof.Input.AuthMethods}
	if err := s.ephemSetJSON(ctx, "account-recovery:"+sha256Hex(token), record, expires.Sub(now)); err != nil {
		return LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LoginOutcome{}, err
	}
	return LoginOutcome{Kind: LoginRecoveryRequired, UserID: proof.Input.UserID, ReturnTo: proof.ReturnTo, Recovery: &AccountRecoveryConfirmation{Token: token, ExpiresAt: expires, PurgeAt: purgeAt}}, nil
}

func (s *engine) ConfirmAccountRecovery(ctx context.Context, token string) error {
	if len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token {
		return jwt.ErrTokenUnverifiable
	}
	key := "account-recovery:" + sha256Hex(token)
	var proof accountRecoveryProof
	raw, ok, err := s.ephemReadJSON(ctx, key, &proof)
	if err != nil {
		return err
	}
	if !ok || proof.Issuer != s.cfg.Token.Issuer || proof.Generation == "" || proof.UserID == "" || proof.Version <= 0 {
		return jwt.ErrTokenUnverifiable
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	user, err := s.lockAuthenticationAccount(ctx, s.qtx(tx), proof.UserID, proof.Version, true)
	if err != nil {
		return err
	}
	if user.DeletedAt == nil {
		return jwt.ErrTokenUnverifiable
	}
	settings, settingsErr := s.get2FASettings(ctx, s.qtx(tx), user.ID)
	status, err := s.MFAStatusWith(settings, settingsErr)
	if err != nil {
		return err
	}
	if err := s.requireSessionMFAStateOn(ctx, tx, user.ID, proof.AuthMethods, status, nil); err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		return err
	}
	if !now.Before(proof.ExpiresAt) {
		return jwt.ErrTokenUnverifiable
	}
	if err := s.claimProof(ctx, key, raw); err != nil {
		return err
	}
	if err := s.restoreAccountDeletionOn(ctx, tx, proof.UserID, proof.Generation); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
