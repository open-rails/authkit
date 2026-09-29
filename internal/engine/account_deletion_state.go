package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/riverqueue/river"
)

type accountDeletionRecord struct {
	iam.UserDeletion
	state      string
	recipients []string
	selfDelete bool // the account deleted itself, so it may restore itself
}

func loadAccountDeletion(ctx context.Context, tx pgx.Tx, id string) (accountDeletionRecord, error) {
	var record accountDeletionRecord
	err := tx.QueryRow(ctx, `SELECT id::text,user_id::text,deleted_at,purge_at,state,recipients,deleted_by IS NOT DISTINCT FROM user_id FROM account_deletions WHERE id=$1::uuid FOR UPDATE`, id).Scan(&record.ID, &record.UserID, &record.DeletedAt, &record.PurgeAt, &record.state, &record.recipients, &record.selfDelete)
	return record, err
}

// createAccountDeletion starts the recovery window. deletedBy is the user who
// deleted the account (nil for the operator); only a self-deletion can be
// undone by signing in.
func (s *Engine) createAccountDeletion(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], userID string, deletedBy *string) error {
	issuers := s.accountIssuers()
	if len(issuers) == 0 {
		return errors.New("authkit: account deletion requires Token.Issuer")
	}
	var deletion iam.UserDeletion
	err := tx.QueryRow(ctx, `INSERT INTO account_deletions(user_id,deleted_at,purge_at,recipients,deleted_by)
 SELECT id,deleted_at,deleted_at+interval '720 hours',$2,$3::uuid FROM users WHERE id=$1::uuid
 RETURNING id::text,user_id::text,deleted_at,purge_at`, userID, issuers, deletedBy).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt)
	if err != nil {
		return err
	}
	return s.scheduleAccountDeletion(ctx, tx, client, deletion, issuers)
}

func (s *Engine) scheduleAccountDeletion(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion iam.UserDeletion, issuers []string) error {
	if err := s.enqueueAccountDeliveries(ctx, tx, client, deletion, issuers, "soft"); err != nil {
		return err
	}
	return s.enqueueAccountFinalizer(ctx, tx, client, deletion, false)
}

func (s *Engine) finalizeAccountDeletion(ctx context.Context, id string, purge bool) error {
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	var userID string
	if err := s.pg.QueryRow(ctx, "SELECT user_id::text FROM account_deletions WHERE id=$1::uuid", id).Scan(&userID); err != nil {
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
	user, err := s.qtx(tx).UserCredentialVersionForUpdate(ctx, userID)
	missingUser := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !missingUser {
		return err
	}
	record, err := loadAccountDeletion(ctx, tx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if record.state == "restored" || record.state == "purged" || (!missingUser && (user.DeletedAt == nil || !user.DeletedAt.Equal(record.DeletedAt))) {
		return nil
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT statement_timestamp()").Scan(&now); err != nil {
		return err
	}
	if now.Before(record.PurgeAt) && !(missingUser && record.state == "finalizing") {
		return river.JobSnooze(record.PurgeAt.Sub(now))
	}
	if err := s.requireOwnersAfterAccountPurge(ctx, store, userID); err != nil {
		return err
	}
	if !purge {
		if record.state != "deleted" {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE account_deletions SET state='finalizing' WHERE id=$1::uuid", id); err != nil {
			return err
		}
		if err := s.enqueueAccountDeliveries(ctx, tx, client, record.UserDeletion, record.recipients, "hard"); err != nil {
			return err
		}
		if len(record.recipients) == 0 {
			if err := s.enqueueAccountFinalizer(ctx, tx, client, record.UserDeletion, true); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	if record.state != "finalizing" {
		return nil
	}
	var pending bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM account_deletion_deliveries WHERE deletion_id=$1::uuid AND stage='hard' AND completed_at IS NULL)", id).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return river.JobSnooze(time.Minute)
	}
	// Sweep while the creator still exists (creator-less credentials are the
	// operator's); the delete then cascades to what the account issued.
	if err := s.revokeCredentialsOf(ctx, store, userID); err != nil {
		return err
	}
	if err := s.qtx(tx).UserDeleteHard(ctx, userID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return fmt.Errorf("%w: %s.%s", errmodel.ErrUserReferenced, pgErr.TableName, pgErr.ConstraintName)
		}
		return fmt.Errorf("authkit: final account purge: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE account_deletions SET state='purged',purged_at=statement_timestamp() WHERE id=$1::uuid", id); err != nil {
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
	rows, err := store.q.Query(ctx, "SELECT permission_group_id::text FROM group_user_roles WHERE user_id=$1::uuid AND role='owner' ORDER BY permission_group_id", userID)
	if err != nil {
		return err
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[string])
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
