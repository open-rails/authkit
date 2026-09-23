package embedded

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

type accountFinalizeArgs struct {
	Schema     string `json:"schema"`
	DeletionID string `json:"deletion_id"`
	Purge      bool   `json:"purge,omitempty"`
}

func (accountFinalizeArgs) Kind() string { return "authkit_account_finalize" }

type accountDeliveryArgs struct {
	Schema     string `json:"schema"`
	Issuer     string `json:"issuer"`
	DeliveryID int64  `json:"delivery_id"`
}

func (accountDeliveryArgs) Kind() string { return "authkit_account_delivery" }

func accountDeliveryQueue(schema, issuer string) string {
	digest := sha256.Sum256([]byte(schema + "\x00" + issuer))
	return "authkit_accounts-" + hex.EncodeToString(digest[:20])
}

func accountFinalizerQueue(schema string) string {
	digest := sha256.Sum256([]byte(schema))
	return "authkit_finalization-" + hex.EncodeToString(digest[:20])
}

func (s *engine) deletionRiver() (*river.Client[pgx.Tx], error) {
	if s.maintenance == nil {
		return nil, errors.New("authkit: account lifecycle requires River")
	}
	s.maintenance.mu.Lock()
	defer s.maintenance.mu.Unlock()
	if s.maintenance.closed || s.maintenance.failed || s.maintenance.client == nil {
		return nil, errors.New("authkit: compose RiverJobs before accepting account lifecycle operations")
	}
	return s.maintenance.client, nil
}

func (s *engine) enqueueAccountFinalizer(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion authkit.UserDeletion, purge bool) error {
	if err := s.requireAccountProducerOn(ctx, tx, client); err != nil {
		return err
	}
	scheduled := deletion.PurgeAt
	if purge {
		scheduled = time.Time{}
	}
	_, err := client.InsertTx(ctx, tx, accountFinalizeArgs{Schema: s.dbSchema(), DeletionID: deletion.ID, Purge: purge}, &river.InsertOpts{Queue: accountFinalizerQueue(s.dbSchema()), ScheduledAt: scheduled})
	return err
}

// The delivery receipt and River row are one transaction. An existing receipt
// therefore already has its durable job; no independent polling queue exists.
func (s *engine) enqueueAccountDeliveries(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion authkit.UserDeletion, issuers []string, stage string) error {
	if err := s.requireAccountProducerOn(ctx, tx, client); err != nil {
		return err
	}
	for _, issuer := range issuers {
		target, err := s.accountDeliveryClient(ctx, tx, client, issuer)
		if err != nil {
			return err
		}
		var id int64
		err = tx.QueryRow(ctx, `INSERT INTO account_deletion_deliveries(deletion_id,user_id,issuer,stage)
 VALUES ($1::uuid,$2::uuid,$3,$4) ON CONFLICT(deletion_id,issuer,stage) DO NOTHING RETURNING id`, deletion.ID, deletion.UserID, issuer, stage).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = target.InsertTx(ctx, tx, accountDeliveryArgs{Schema: s.dbSchema(), Issuer: issuer, DeliveryID: id}, &river.InsertOpts{Queue: accountDeliveryQueue(s.dbSchema(), issuer)})
		if err != nil {
			return err
		}
	}
	return nil
}

// Register the durable destination before accepting account mutations. Every
// configured account issuer must bind once before deletion can affect it. An
// offline registered application still receives durable jobs in its own fleet.
func (s *engine) registerAccountDeliveryFleet(ctx context.Context, client *river.Client[pgx.Tx]) error {
	if s.cfg.Token.Issuer == "" {
		return nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO account_delivery_fleets(issuer,river_schema) VALUES ($1,$2) ON CONFLICT(issuer) DO NOTHING`, s.cfg.Token.Issuer, client.Schema()); err != nil {
		return err
	}
	var registered string
	if err := tx.QueryRow(ctx, "SELECT river_schema FROM account_delivery_fleets WHERE issuer=$1 FOR UPDATE", s.cfg.Token.Issuer).Scan(&registered); err != nil {
		return err
	}
	if registered != client.Schema() {
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM account_deletion_deliveries WHERE issuer=$1 AND completed_at IS NULL)
 OR EXISTS(SELECT 1 FROM account_deletions WHERE state IN ('deleted','finalizing') AND $1=ANY(recipients))`, s.cfg.Token.Issuer).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return fmt.Errorf("authkit: issuer %q still has active account lifecycle work in River schema %q; finish that work before rebinding its fleet", s.cfg.Token.Issuer, registered)
		}
		if _, err := tx.Exec(ctx, "UPDATE account_delivery_fleets SET river_schema=$2 WHERE issuer=$1", s.cfg.Token.Issuer, client.Schema()); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.warnUnboundAccountIssuers(ctx)
	return nil
}

// Account deletion fails closed until every account issuer has started once
// against this database; say so at startup, not only in a failed request.
func (s *engine) warnUnboundAccountIssuers(ctx context.Context) {
	var unbound []string
	err := s.pg.QueryRow(ctx, `SELECT coalesce(array_agg(i ORDER BY i),'{}') FROM unnest($1::text[]) i
 WHERE NOT EXISTS (SELECT 1 FROM account_delivery_fleets f WHERE f.issuer=i)`, s.accountIssuers()).Scan(&unbound)
	if err != nil || len(unbound) == 0 {
		return
	}
	slog.WarnContext(ctx, "authkit: account deletion fails until these account issuers start against this database", "issuers", unbound)
}

// Fence a previously bound runtime after a quiescent schema switch. Holding
// this shared row lock until the account transaction commits also prevents a
// rebind from racing new lifecycle jobs into the former destination.
func (s *engine) requireAccountProducerOn(ctx context.Context, tx pgx.Tx, local *river.Client[pgx.Tx]) error {
	var schema string
	if err := tx.QueryRow(ctx, "SELECT river_schema FROM account_delivery_fleets WHERE issuer=$1 FOR SHARE", s.cfg.Token.Issuer).Scan(&schema); err != nil {
		return err
	}
	if schema != local.Schema() {
		return errors.New("authkit: this runtime's account River fleet was rebound; recreate the runtime with the current fleet schema")
	}
	return nil
}

func (s *engine) accountDeliveryClient(ctx context.Context, tx pgx.Tx, local *river.Client[pgx.Tx], issuer string) (*river.Client[pgx.Tx], error) {
	if issuer == s.cfg.Token.Issuer {
		return local, nil // requireAccountProducerOn already locked this mapping.
	}
	var schema string
	if err := tx.QueryRow(ctx, "SELECT river_schema FROM account_delivery_fleets WHERE issuer=$1 FOR SHARE", issuer).Scan(&schema); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("authkit: account issuer %q must compose its River fleet before account deletion", issuer)
		}
		return nil, err
	}
	if schema == local.Schema() {
		return local, nil
	}
	// Insert-only client: no worker registry, start/stop, polling or owned pool.
	// InsertTx writes into this fleet's schema using the same account transaction.
	return river.NewClient(riverpgxv5.New(s.pg), &river.Config{Schema: schema})
}

type accountDeliveryWorker struct {
	river.WorkerDefaults[accountDeliveryArgs]
	engine *engine
}

func (w *accountDeliveryWorker) Work(ctx context.Context, job *river.Job[accountDeliveryArgs]) error {
	if job.Args.Schema != w.engine.dbSchema() || job.Args.Issuer != w.engine.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: account delivery routed to a different application"))
	}
	err := w.engine.deliverAccountEvent(ctx, job.Args.DeliveryID)
	if err == nil {
		return nil
	}
	var snooze *river.JobSnoozeError
	if errors.As(err, &snooze) {
		return err
	}
	// Lifecycle callback failure never exhausts the attempt budget and drops
	// cleanup. River owns the scheduled retry; the receipt remains pending.
	slog.ErrorContext(ctx, "authkit: account callback will retry", "delivery_id", job.Args.DeliveryID, "error", err)
	return river.JobSnooze(time.Minute)
}

func (s *engine) deliverAccountEvent(ctx context.Context, id int64) error {
	var userID string
	err := s.pg.QueryRow(ctx, "SELECT user_id::text FROM account_deletion_deliveries WHERE id=$1", id).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	// River is at least once. Serialize a user's callbacks across replicas and
	// rescued attempts, then reread the receipt. A dedicated connection keeps
	// the host's one-slot pool available for callback code and holds no table
	// transaction while application code runs.
	lock, err := pgx.ConnectConfig(ctx, s.pg.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lock.Close(cleanup)
	}()
	key := "authkit-account-callback:" + s.dbSchema() + ":" + s.cfg.Token.Issuer + ":" + userID
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_lock(hashtext(current_database()),hashtext($1))", key); err != nil {
		return err
	}
	var deletion authkit.UserDeletion
	var issuer, stage string
	var completed *time.Time
	err = s.pg.QueryRow(ctx, `SELECT d.id::text,d.user_id::text,d.deleted_at,d.purge_at,e.issuer,e.stage,e.completed_at
 FROM account_deletion_deliveries e JOIN account_deletions d ON d.id=e.deletion_id WHERE e.id=$1`, id).Scan(&deletion.ID, &deletion.UserID, &deletion.DeletedAt, &deletion.PurgeAt, &issuer, &stage, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if completed != nil {
		return nil
	}
	if issuer != s.cfg.Token.Issuer {
		return errors.New("authkit: account delivery issuer mismatch")
	}
	var preceding bool
	err = s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM account_deletion_deliveries WHERE user_id=$1::uuid AND issuer=$2 AND id<$3 AND completed_at IS NULL)`, deletion.UserID, issuer, id).Scan(&preceding)
	if err != nil {
		return err
	}
	if preceding {
		return river.JobSnooze(time.Second)
	}
	var hook func(context.Context, authkit.UserDeletion) error
	switch stage {
	case "soft":
		hook = s.onSoftDelete
	case "hard":
		hook = s.onHardDelete
	case "restore":
		hook = s.onRestore
	default:
		return fmt.Errorf("authkit: unsupported account lifecycle stage %q", stage)
	}
	// No pool connection or database transaction is held while application
	// code runs. A hook may safely call the Client with a one-slot pool.
	if hook != nil {
		if err := invokeAccountHook(ctx, hook, deletion); err != nil {
			return err
		}
	}
	client, err := s.deletionRiver()
	if err != nil {
		return err
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var state string
	if err := tx.QueryRow(ctx, "SELECT state FROM account_deletions WHERE id=$1::uuid FOR UPDATE", deletion.ID).Scan(&state); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, "UPDATE account_deletion_deliveries SET completed_at=statement_timestamp() WHERE id=$1 AND completed_at IS NULL", id)
	if err != nil {
		return err
	}
	if stage == "hard" && state == "finalizing" && result.RowsAffected() == 1 {
		var pending bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM account_deletion_deliveries WHERE deletion_id=$1::uuid AND stage='hard' AND completed_at IS NULL)", deletion.ID).Scan(&pending); err != nil {
			return err
		}
		if !pending {
			if err := s.enqueueAccountFinalizer(ctx, tx, client, deletion, true); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func invokeAccountHook(ctx context.Context, hook func(context.Context, authkit.UserDeletion) error, deletion authkit.UserDeletion) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("account lifecycle callback panicked: %v", recovered)
		}
	}()
	return hook(ctx, deletion)
}

type accountFinalizeWorker struct {
	river.WorkerDefaults[accountFinalizeArgs]
	engine *engine
}

func (w *accountFinalizeWorker) Work(ctx context.Context, job *river.Job[accountFinalizeArgs]) error {
	if job.Args.Schema != w.engine.dbSchema() {
		return river.JobCancel(errors.New("authkit: account finalizer schema mismatch"))
	}
	err := w.engine.finalizeAccountDeletion(ctx, job.Args.DeletionID, job.Args.Purge)
	if err == nil {
		return nil
	}
	var snooze *river.JobSnoozeError
	if errors.As(err, &snooze) {
		return err
	}
	slog.ErrorContext(ctx, "authkit: account finalization will retry", "deletion_id", job.Args.DeletionID, "error", err)
	return river.JobSnooze(time.Minute)
}
