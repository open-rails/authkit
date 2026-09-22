package embedded

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	authkit "github.com/open-rails/authkit"
	"github.com/riverqueue/river"
)

type accountDeletionRecord struct {
	authkit.UserDeletion
	state      string
	recipients []string
}

func loadAccountDeletion(ctx context.Context, tx pgx.Tx, id string) (accountDeletionRecord, error) {
	var record accountDeletionRecord
	err := tx.QueryRow(ctx, `SELECT id::text,user_id::text,deleted_at,purge_at,state,recipients FROM account_deletions WHERE id=$1::uuid FOR UPDATE`, id).Scan(&record.ID, &record.UserID, &record.DeletedAt, &record.PurgeAt, &record.state, &record.recipients)
	return record, err
}

func (s *engine) createAccountDeletion(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], userID string) error {
	issuers := s.accountIssuers()
	if len(issuers) == 0 {
		return errors.New("authkit: account deletion requires Token.Issuer")
	}
	var deletion authkit.UserDeletion
	err := tx.QueryRow(ctx, `INSERT INTO account_deletions(user_id,deleted_at,purge_at,recipients)
 SELECT id,deleted_at,deleted_at+interval '720 hours',$2 FROM users WHERE id=$1::uuid
 RETURNING id::text,user_id::text,deleted_at,purge_at`, userID, issuers).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt)
	if err != nil {
		return err
	}
	return s.scheduleAccountDeletion(ctx, tx, client, deletion, issuers)
}

func (s *engine) scheduleAccountDeletion(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion authkit.UserDeletion, issuers []string) error {
	if err := s.enqueueAccountDeliveries(ctx, tx, client, deletion, issuers, "soft"); err != nil {
		return err
	}
	if err := s.enqueueAccountFinalizer(ctx, tx, client, deletion, false); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, "UPDATE account_deletions SET jobs_enqueued=true,recipients=$2 WHERE id=$1::uuid", deletion.ID, issuers)
	return err
}

// adoptAccountDeletions is upgrade initialization only. New deletion requests
// enqueue directly in their transaction; workers never scan this table for work.
func (s *engine) adoptAccountDeletions(ctx context.Context, client *river.Client[pgx.Tx]) error {
	for {
		tx, err := s.pg.Begin(ctx)
		if err != nil {
			return err
		}
		var record accountDeletionRecord
		err = tx.QueryRow(ctx, `SELECT id::text,user_id::text,deleted_at,purge_at,state,recipients FROM account_deletions d
 WHERE NOT jobs_enqueued AND state IN ('deleted','finalizing')
 AND NOT EXISTS(SELECT 1 FROM unnest(CASE WHEN cardinality(d.recipients)=0 THEN $1::text[] ELSE d.recipients END) AS required(issuer)
   LEFT JOIN account_delivery_fleets f ON f.issuer=required.issuer WHERE f.issuer IS NULL)
 ORDER BY deleted_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, s.accountIssuers()).Scan(&record.ID, &record.UserID, &record.DeletedAt, &record.PurgeAt, &record.state, &record.recipients)
		if errors.Is(err, pgx.ErrNoRows) {
			_ = tx.Rollback(ctx)
			return nil
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		issuers := record.recipients
		if len(issuers) == 0 {
			issuers = s.accountIssuers()
		}
		if len(issuers) == 0 {
			_ = tx.Rollback(ctx)
			return errors.New("authkit: pending account deletion requires Token.Issuer")
		}
		if record.state == "finalizing" {
			err = s.enqueueAccountDeliveries(ctx, tx, client, record.UserDeletion, issuers, "hard")
			if err == nil {
				_, err = tx.Exec(ctx, "UPDATE account_deletions SET jobs_enqueued=true WHERE id=$1::uuid", record.ID)
			}
		} else {
			err = s.scheduleAccountDeletion(ctx, tx, client, record.UserDeletion, issuers)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
}

func (s *engine) finalizeAccountDeletion(ctx context.Context, id string, purge bool) error {
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
	if err := s.qtx(tx).UserDeleteHard(ctx, userID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return fmt.Errorf("%w: %s.%s", ErrUserReferenced, pgErr.TableName, pgErr.ConstraintName)
		}
		return fmt.Errorf("authkit: final account purge: %w", err)
	}
	if _, err := tx.Exec(ctx, "UPDATE account_deletions SET state='purged',purged_at=statement_timestamp() WHERE id=$1::uuid", id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A deleted subject is already unusable. Recheck the remaining owners directly
// rather than treating that fact as permission to orphan a group during purge.
func (s *engine) requireOwnersAfterAccountPurge(ctx context.Context, store *PermissionGroupStore, userID string) error {
	rows, err := store.q.Query(ctx, "SELECT permission_group_id::text FROM group_user_roles WHERE user_id=$1::uuid AND role='owner' ORDER BY permission_group_id", userID)
	if err != nil {
		return err
	}
	groups, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, groupID := range groups {
		if err := s.requireRemainingOwner(ctx, store, groupID, authkit.UserSubject(userID)); err != nil {
			return err
		}
	}
	return nil
}
