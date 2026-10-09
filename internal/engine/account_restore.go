package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/helpers/auth"
)

// restoreAccountDeletionOn is the common transactional restore transition.
// Recovery proofs must pass their server-bound generation; system restores
// pass an empty generation to select the current deletion. Callers retain
// responsibility for authenticating a, their identity, before invoking this helper.
func (s *Engine) restoreAccountDeletionOn(ctx context.Context, tx pgx.Tx, a auth.Identity, userID, generation string) error {
	if _, err := s.deletionRiver(); err != nil {
		return err
	}
	q := s.qtx(tx)
	user, err := q.UserCredentialVersionForUpdate(ctx, userID)
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
	id, err := q.AccountDeletionOpenForUser(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if err != nil {
		return err
	}
	if generation != "" && generation != id {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	record, err := q.AccountDeletionForUpdate(ctx, id)
	if err != nil {
		return err
	}
	now, err := q.StatementTimestamp(ctx)
	if err != nil {
		return err
	}
	if record.State != "deleted" || !now.Before(record.PurgeAt) || !user.DeletedAt.Equal(record.DeletedAt) {
		return errmodel.E(errmodel.CodeAccountRecoveryExpired)
	}
	if generation != "" && !selfDeleted(record) {
		return errmodel.E(errmodel.CodeAccountDisabled)
	}
	// Clearing deleted_at uses the same credential-version invalidation trigger
	// as deletion; no proof from the deleted state becomes a normal login proof.
	if err := q.UserRestore(ctx, userID); err != nil {
		return err
	}
	if err := q.AccountDeletionSetRestored(ctx, id); err != nil {
		return err
	}
	return s.emitEvents(ctx, tx, a, userEvent(iam.EventUserRestored, userID))
}
