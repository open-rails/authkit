package engine

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
)

type accountRecoveryProof struct {
	AuthMethods []string  `json:"auth_methods"`
	UserID      string    `json:"user_id"`
	Generation  string    `json:"generation"`
	Issuer      string    `json:"issuer"`
	Version     int64     `json:"version"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (s *Engine) ensureLoginProofAccess(ctx context.Context, user *db.User) error {
	if user == nil {
		return jwt.ErrTokenUnverifiable
	}
	copy := *user
	copy.DeletedAt = nil
	return s.ensureUserAccess(ctx, &copy)
}

// Called with the account row locked; a normal in-flight proof cannot cross a
// credential-version change or switch to a later deletion cycle.
func (s *Engine) bindRecoveryGeneration(ctx context.Context, tx pgx.Tx, user *db.User, proof *loginProof) error {
	if user.DeletedAt == nil {
		if proof.DeletionID != "" {
			return jwt.ErrTokenUnverifiable
		}
		return nil
	}
	deletion, err := s.qtx(tx).AccountDeletionRecoverable(ctx, db.AccountDeletionRecoverableParams{UserID: user.ID, DeletedAt: *user.DeletedAt})
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	// Only a self-deletion is undone by signing in; an account staff or the
	// system deleted comes back only through RestoreUsers (N5).
	if !selfDeleted(deletion) {
		return errmodel.E(errmodel.CodeAccountDisabled)
	}
	if proof.DeletionID != "" && proof.DeletionID != deletion.ID {
		return jwt.ErrTokenUnverifiable
	}
	proof.DeletionID = deletion.ID
	return nil
}

func (s *Engine) finishRecoveryProof(ctx context.Context, tx pgx.Tx, proof loginProof) (authflow.LoginOutcome, error) {
	window, err := s.qtx(tx).AccountDeletionPurgeWindow(ctx, db.AccountDeletionPurgeWindowParams{ID: proof.DeletionID, UserID: proof.Input.UserID})
	if err != nil {
		return authflow.LoginOutcome{}, err
	}
	now, purgeAt := window.Now, window.PurgeAt
	expires := now.Add(10 * time.Minute)
	if purgeAt.Before(expires) {
		expires = purgeAt
	}
	token := secret.Token(32)
	record := accountRecoveryProof{UserID: proof.Input.UserID, Generation: proof.DeletionID, Issuer: s.cfg.Token.Issuer, Version: proof.Version, ExpiresAt: expires, AuthMethods: proof.Input.AuthMethods}
	if err := s.ephemSetJSON(ctx, "account-recovery:"+secret.Hash(token), record, expires.Sub(now)); err != nil {
		return authflow.LoginOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return authflow.LoginOutcome{}, err
	}
	return authflow.LoginOutcome{Kind: authflow.LoginRecoveryRequired, UserID: proof.Input.UserID, ReturnTo: proof.ReturnTo, Recovery: &authflow.AccountRecoveryConfirmation{Token: token, ExpiresAt: expires, PurgeAt: purgeAt}}, nil
}

func (s *Engine) ConfirmAccountRecovery(ctx context.Context, token string) error {
	if len(token) < 32 || len(token) > 256 || strings.TrimSpace(token) != token {
		return jwt.ErrTokenUnverifiable
	}
	key := "account-recovery:" + secret.Hash(token)
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
	status, err := s.mfaStatusWith(settings, settingsErr)
	if err != nil {
		return err
	}
	if err := s.requireSessionMFAStateOn(ctx, tx, user.ID, proof.AuthMethods, status, nil); err != nil {
		return err
	}
	now, err := s.qtx(tx).StatementTimestamp(ctx)
	if err != nil {
		return err
	}
	if !now.Before(proof.ExpiresAt) {
		return jwt.ErrTokenUnverifiable
	}
	if err := s.claimProof(ctx, key, raw); err != nil {
		return err
	}
	if err := s.restoreAccountDeletionOn(ctx, tx, iam.UserActor(proof.UserID), proof.UserID, proof.Generation); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
