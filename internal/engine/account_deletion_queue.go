package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
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

func (s *Engine) deletionRiver() (*river.Client[pgx.Tx], error) {
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

func (s *Engine) enqueueAccountFinalizer(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion iam.UserDeletion, purge bool) error {
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
func (s *Engine) enqueueAccountDeliveries(ctx context.Context, tx pgx.Tx, client *river.Client[pgx.Tx], deletion iam.UserDeletion, issuers []string, stage string) error {
	if err := s.requireAccountProducerOn(ctx, tx, client); err != nil {
		return err
	}
	for _, issuer := range issuers {
		target, err := s.accountDeliveryClient(ctx, tx, client, issuer)
		if err != nil {
			return err
		}
		id, err := s.qtx(tx).AccountDeletionDeliveryInsert(ctx, db.AccountDeletionDeliveryInsertParams{DeletionID: deletion.ID, UserID: deletion.UserID, Issuer: issuer, Stage: stage})
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
func (s *Engine) registerAccountDeliveryFleet(ctx context.Context, client *river.Client[pgx.Tx]) error {
	if s.cfg.Token.Issuer == "" {
		return nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q, issuer := s.qtx(tx), s.cfg.Token.Issuer
	if err := q.AccountDeliveryFleetInsert(ctx, db.AccountDeliveryFleetInsertParams{Issuer: issuer, RiverSchema: client.Schema()}); err != nil {
		return err
	}
	registered, err := q.AccountDeliveryFleetSchemaForUpdate(ctx, issuer)
	if err != nil {
		return err
	}
	if registered != client.Schema() {
		busy, err := q.AccountDeliveryFleetBusy(ctx, issuer)
		if err != nil {
			return err
		}
		if busy {
			return fmt.Errorf("authkit: issuer %q still has active account lifecycle work in River schema %q; finish that work before rebinding its fleet", issuer, registered)
		}
		if err := q.AccountDeliveryFleetSetSchema(ctx, db.AccountDeliveryFleetSetSchemaParams{Issuer: issuer, RiverSchema: client.Schema()}); err != nil {
			return err
		}
	}
	// A deployment with OnEvent subscribes its issuer to events from now on;
	// one without unsubscribes, and what is pending is still delivered.
	if err := q.AccountDeliveryFleetSetEvents(ctx, db.AccountDeliveryFleetSetEventsParams{Issuer: issuer, Events: s.onEvent != nil}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.warnUnboundAccountIssuers(ctx)
	return nil
}

// Account deletion fails closed until every account issuer has started once
// against this database; say so at startup, not only in a failed request.
func (s *Engine) warnUnboundAccountIssuers(ctx context.Context) {
	unbound, err := s.q.AccountDeliveryFleetsUnbound(ctx, s.accountIssuers())
	if err != nil || len(unbound) == 0 {
		return
	}
	slog.WarnContext(ctx, "authkit: account deletion fails until these account issuers start against this database", "issuers", unbound)
}

// Fence a previously bound runtime after a quiescent schema switch. Holding
// this shared row lock until the account transaction commits also prevents a
// rebind from racing new lifecycle jobs into the former destination.
func (s *Engine) requireAccountProducerOn(ctx context.Context, tx pgx.Tx, local *river.Client[pgx.Tx]) error {
	schema, err := s.qtx(tx).AccountDeliveryFleetSchemaForShare(ctx, s.cfg.Token.Issuer)
	if err != nil {
		return err
	}
	if schema != local.Schema() {
		return errors.New("authkit: this runtime's account River fleet was rebound; recreate the runtime with the current fleet schema")
	}
	return nil
}

func (s *Engine) accountDeliveryClient(ctx context.Context, tx pgx.Tx, local *river.Client[pgx.Tx], issuer string) (*river.Client[pgx.Tx], error) {
	if issuer == s.cfg.Token.Issuer {
		return local, nil // requireAccountProducerOn already locked this mapping.
	}
	schema, err := s.qtx(tx).AccountDeliveryFleetSchemaForShare(ctx, issuer)
	if err != nil {
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
	return river.NewClient(riverpgxv5.New(s.pg), riverConfig(schema))
}

type accountDeliveryWorker struct {
	river.WorkerDefaults[accountDeliveryArgs]
	engine *Engine
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

func (s *Engine) deliverAccountEvent(ctx context.Context, id int64) error {
	userID, err := s.q.AccountDeletionDeliveryUser(ctx, id)
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
	if err := db.New(lock).AccountDeliveryLock(ctx, key); err != nil {
		return err
	}
	delivery, err := s.q.AccountDeletionDelivery(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if delivery.CompletedAt != nil {
		return nil
	}
	if delivery.Issuer != s.cfg.Token.Issuer {
		return errors.New("authkit: account delivery issuer mismatch")
	}
	deletion := userDeletion(delivery.AccountDeletion)
	preceding, err := s.q.AccountDeletionDeliveryEarlierPending(ctx, db.AccountDeletionDeliveryEarlierPendingParams{UserID: deletion.UserID, Issuer: delivery.Issuer, ID: id})
	if err != nil {
		return err
	}
	if preceding {
		return river.JobSnooze(time.Second)
	}
	stage := delivery.Stage
	var hook func(context.Context, iam.UserDeletion) error
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
	// code runs. A hook may safely call Client with a one-slot pool.
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
	q := s.qtx(tx)
	state, err := q.AccountDeletionStateForUpdate(ctx, deletion.ID)
	if err != nil {
		return err
	}
	completed, err := q.AccountDeletionDeliveryComplete(ctx, id)
	if err != nil {
		return err
	}
	if stage == "hard" && state == "finalizing" && completed == 1 {
		pending, err := q.AccountDeletionHardDeliveriesPending(ctx, deletion.ID)
		if err != nil {
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

func invokeAccountHook(ctx context.Context, hook func(context.Context, iam.UserDeletion) error, deletion iam.UserDeletion) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("account lifecycle callback panicked: %v", recovered)
		}
	}()
	return hook(ctx, deletion)
}

type accountFinalizeWorker struct {
	river.WorkerDefaults[accountFinalizeArgs]
	engine *Engine
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
