package engine

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// restoreAccountDeletionOn is the common transactional restore transition.
// Recovery proofs must pass their server-bound generation; system restores
// pass an empty generation to select the current deletion. Callers retain
// responsibility for authenticating a, their actor, before invoking this helper.
func (s *Engine) restoreAccountDeletionOn(ctx context.Context, tx pgx.Tx, a iam.Actor, userID, generation string) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	user, err := s.qtx(tx).UserCredentialVersionForUpdate(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.E(errmodel.CodeUserNotFound)
	}
	if err != nil {
		return err
	}
	if user.DeletedAt == nil {
		if generation != "" {
			return errmodel.E(errmodel.CodeAccountRecoveryExpired)
		}
		return nil
	}
	var id string
	err = tx.QueryRow(ctx, "SELECT id::text FROM account_deletions WHERE user_id=$1::uuid AND state IN ('deleted','finalizing')", userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	if generation != "" && generation != id {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
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
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if generation != "" && !record.selfDelete {
		return errmodel.E(errmodel.CodeAccountDisabled)
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
	return s.emitEvents(ctx, tx, a, userEvent(iam.EventUserRestored, userID))
}
