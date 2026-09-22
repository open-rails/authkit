package embedded

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
)

// OperatorRestoreUsers restores accounts under explicit trusted host authority.
// It never revives old sessions, device keys or an expired deletion generation.
func (s *engine) OperatorRestoreUsers(ctx context.Context, userIDs []string) ([]authkit.OpResult, error) {
	out := make([]authkit.OpResult, 0, len(userIDs))
	for _, id := range userIDs {
		out = append(out, authkit.OpResult{ID: id, Err: s.restoreUser(ctx, "", id)})
	}
	return out, nil
}

func (s *engine) RestoreUserAs(ctx context.Context, actorUserID, userID string) error {
	if strings.TrimSpace(actorUserID) == "" {
		return ErrInsufficientRoleAuthority
	}
	return s.restoreUser(ctx, actorUserID, userID)
}

func (s *engine) restoreUser(ctx context.Context, actorUserID, userID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	store := s.groupStoreFor(tx)
	if err := s.lockAuthority(ctx, store.q); err != nil {
		return err
	}
	if actorUserID != "" {
		if err := s.authorizeAccountAuthorityOn(ctx, store, actorUserID, userID); err != nil {
			return err
		}
	}
	if err := s.restoreAccountDeletionOn(ctx, tx, userID, ""); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// restoreAccountDeletionOn is the common transactional restore transition.
// Recovery proofs must pass their server-bound generation; trusted operators
// pass an empty generation to select the current deletion. Callers retain
// responsibility for authenticating their actor before invoking this helper.
func (s *engine) restoreAccountDeletionOn(ctx context.Context, tx pgx.Tx, userID, generation string) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	user, err := s.qtx(tx).UserCredentialVersionForUpdate(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.E(authkit.CodeUserNotFound)
	}
	if err != nil {
		return err
	}
	if user.DeletedAt == nil {
		if generation != "" {
			return authkit.E(authkit.CodeAccountRecoveryExpired)
		}
		return nil
	}
	var id string
	err = tx.QueryRow(ctx, "SELECT id::text FROM account_deletions WHERE user_id=$1::uuid AND state IN ('deleted','finalizing')", userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return authkit.E(authkit.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	if generation != "" && generation != id {
		return authkit.E(authkit.CodeAccountRecoveryExpired)
	}
	record, err := loadAccountDeletion(ctx, tx, id)
	if err != nil {
		return err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		return err
	}
	if record.state != "deleted" || !now.Before(record.PurgeAt) || !user.DeletedAt.Equal(record.DeletedAt) {
		return authkit.E(authkit.CodeAccountRecoveryExpired)
	}
	// Clearing deleted_at uses the same credential-version invalidation trigger
	// as deletion; no proof from the deleted state becomes a normal login proof.
	if _, err := tx.Exec(ctx, "UPDATE users SET deleted_at=NULL,updated_at=statement_timestamp() WHERE id=$1::uuid", userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "UPDATE account_deletions SET state='restored',restored_at=statement_timestamp() WHERE id=$1::uuid", id); err != nil {
		return err
	}
	if err := s.enqueueAccountDeliveries(ctx, tx, client, record.UserDeletion, record.recipients, "restore"); err != nil {
		return err
	}
	return nil
}
