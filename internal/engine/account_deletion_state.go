package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/riverqueue/river"
)

// userDeletion is Deps.OnPurge's view of a deletion.
func userDeletion(d db.AccountDeletion) iam.UserDeletion {
	return iam.UserDeletion{ID: d.ID, UserID: d.UserID, DeletedAt: d.DeletedAt, PurgeAt: d.PurgeAt}
}

// selfDeleted reports that the account deleted itself, so it may restore
// itself.
func selfDeleted(d db.AccountDeletion) bool {
	return d.DeletedBy != nil && *d.DeletedBy == d.UserID
}

// createAccountDeletion starts the recovery window. deletedBy is the user who
// deleted the account (nil for the system); only a self-deletion can be
// undone by signing in.
func (s *Engine) createAccountDeletion(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], userID string, deletedBy *string) error {
	issuers := s.accountIssuers()
	if len(issuers) == 0 {
		return errors.New("authkit: account deletion requires Token.Issuer")
	}
	// Every recipient's OnPurge runs before the purge: refuse now, not 30
	// days later, while an account issuer has never bound its fleet.
	for _, issuer := range issuers[1:] {
		if _, err := s.qtx(tx).AccountDeliveryFleetSchemaForShare(ctx, issuer); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("authkit: account issuer %q must boot against this database before account deletion", issuer)
			}
			return err
		}
	}
	deletion, err := s.qtx(tx).AccountDeletionInsert(ctx, db.AccountDeletionInsertParams{UserID: userID, Recipients: issuers, DeletedBy: deletedBy})
	if err != nil {
		return err
	}
	return s.enqueueAccountFinalizer(ctx, tx, client, userDeletion(deletion), false)
}

func (s *Engine) finalizeAccountDeletion(ctx context.Context, id string, purge bool) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	userID, err := s.q.AccountDeletionUser(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
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
	q := s.qtx(tx)
	user, err := q.UserCredentialVersionForUpdate(ctx, userID)
	missingUser := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !missingUser {
		return err
	}
	record, err := q.AccountDeletionForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.State == "restored" || record.State == "purged" || (!missingUser && (user.DeletedAt == nil || !user.DeletedAt.Equal(record.DeletedAt))) {
		return nil
	}
	now, err := q.StatementTimestamp(ctx)
	if err != nil {
		return err
	}
	if now.Before(record.PurgeAt) && !(missingUser && record.State == "finalizing") {
		return river.JobSnooze(record.PurgeAt.Sub(now))
	}
	if err := s.requireOwnersAfterAccountPurge(ctx, store, userID); err != nil {
		return err
	}
	if !purge {
		if record.State != "deleted" {
			return nil
		}
		if err := q.AccountDeletionSetFinalizing(ctx, id); err != nil {
			return err
		}
		if err := s.enqueueAccountDeliveries(ctx, tx, client, userDeletion(record), record.Recipients, "hard"); err != nil {
			return err
		}
		if len(record.Recipients) == 0 {
			if err := s.enqueueAccountFinalizer(ctx, tx, client, userDeletion(record), true); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	if record.State != "finalizing" {
		return nil
	}
	pending, err := q.AccountDeletionHardDeliveriesPending(ctx, id)
	if err != nil {
		return err
	}
	if pending {
		return river.JobSnooze(time.Minute)
	}
	// Sweep while the creator still exists (creator-less credentials are the
	// system's); the delete then cascades to what the account issued.
	if err := s.revokeCredentialsOf(ctx, store, userID); err != nil {
		return err
	}
	if err := q.UserDeleteHard(ctx, userID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return fmt.Errorf("%w: %s.%s", errmodel.ErrUserReferenced, pgErr.TableName, pgErr.ConstraintName)
		}
		return fmt.Errorf("authkit: final account purge: %w", err)
	}
	if err := q.AccountDeletionSetPurged(ctx, id); err != nil {
		return err
	}
	if err := store.record(ctx, userEvent(iam.EventUserPurged, userID)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A deleted subject is already unusable. Recheck the remaining owners directly
// rather than treating that fact as permission to orphan a group during purge.
func (s *Engine) requireOwnersAfterAccountPurge(ctx context.Context, store *permissionGroupStore, userID string) error {
	groups, err := db.New(store.q).GroupsOwnedByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, groupID := range groups {
		if err := s.requireRemainingOwner(ctx, store, groupID, iam.UserSubject(userID)); err != nil {
			return err
		}
	}
	return nil
}
