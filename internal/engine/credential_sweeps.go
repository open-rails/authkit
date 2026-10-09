package engine

// Rule CRED across the apps sharing an account store: each judges only the
// credentials it issued, under its own role catalog. An authority change made
// through one app has every other account issuer sweep its own, by a job its
// fleet receives in the change's transaction.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/helpers/auth"
)

type credentialSweepArgs struct {
	Schema  string                 `json:"schema"`
	Issuer  string                 `json:"issuer"`
	Touches []credentialSweepTouch `json:"touches"`
}

type credentialSweepTouch struct {
	GroupID string `json:"group_id"`
	UserID  string `json:"user_id,omitempty"`
}

func (credentialSweepArgs) Kind() string { return "authkit_credential_sweep" }

func credentialSweepQueue(schema, issuer string) string {
	digest := sha256.Sum256([]byte(schema + "\x00" + issuer))
	return "authkit_credentials-" + hex.EncodeToString(digest[:20])
}

// enqueuePeerCredentialSweeps has every other account issuer with a bound
// fleet sweep touched. One that never bound a fleet issued nothing it alone
// judges; this app swept what every app judges.
func (s *Engine) enqueuePeerCredentialSweeps(ctx context.Context, q db.DBTX, touched []authorityTouch) error {
	peers := s.accountIssuers()[1:]
	if len(peers) == 0 || len(touched) == 0 {
		return nil
	}
	tx, ok := q.(pgx.Tx)
	if !ok {
		return errors.New("authkit: credential sweeps are enqueued only in the transaction of their change")
	}
	fleets, err := s.qtx(tx).CredentialSweepFleetsForShare(ctx, peers)
	if err != nil || len(fleets) == 0 {
		return err
	}
	touches := make([]credentialSweepTouch, len(touched))
	for i, t := range touched {
		touches[i] = credentialSweepTouch{GroupID: t.groupID, UserID: t.userID}
	}
	for _, f := range fleets {
		client, err := s.fleetProducer(f.RiverSchema)
		if err != nil {
			return err
		}
		args := credentialSweepArgs{Schema: s.dbSchema(), Issuer: f.Issuer, Touches: touches}
		if _, err := client.InsertTx(ctx, tx, args, &river.InsertOpts{Queue: credentialSweepQueue(s.dbSchema(), f.Issuer)}); err != nil {
			return err
		}
	}
	return nil
}

type credentialSweepWorker struct {
	river.WorkerDefaults[credentialSweepArgs]
	engine *Engine
}

// Work sweeps what this app issued in the scope of another app's change, under
// the authority lock. The change is made: the sweep retires and never refuses.
func (w *credentialSweepWorker) Work(ctx context.Context, job *river.Job[credentialSweepArgs]) error {
	if job.Args.Schema != w.engine.dbSchema() || job.Args.Issuer != w.engine.cfg.Token.Issuer {
		return river.JobCancel(errors.New("authkit: credential sweep routed to a different application"))
	}
	return w.engine.withAuthorityMutation(ctx, auth.Identity{}, func(st *permissionGroupStore) error {
		st.reconcile = true
		for _, t := range job.Args.Touches {
			st.touched = append(st.touched, authorityTouch{groupID: t.GroupID, userID: t.UserID})
		}
		return nil
	})
}
