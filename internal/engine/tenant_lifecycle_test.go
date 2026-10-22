package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/tenancy"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

func TestTenantLifecycleRetainsTargetAcrossRestartAndPurge(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	cfg := maintenanceConfig()
	schema := "tenant_lifecycle_" + uniqueSuffix()
	cfg.Database.Schema, cfg.Database.RiverSchema = schema, schema
	cfg.Roles = config.NewRoles(config.CustomRoles)
	app := cfg.Roles.Persona("workspace")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
		_, err = pool.Exec(ctx, "DELETE FROM public.migrations WHERE app='authkit' AND schema=$1", schema)
		require.NoError(t, err)
	})
	target := iam.NewTenantID()
	var userID, groupID, rootID string
	var received []iam.Event
	var purges []iam.UserDeletion
	retryPurge := true
	deps := config.Deps{
		Postgres: pool,
		OnEvent: func(ctx context.Context, event iam.Event) error {
			owner, bound := tenancy.From(ctx)
			require.True(t, bound, "event delivery must choose or explicitly clear its target")
			require.Equal(t, event.TenantID, owner)
			if event.UserID == userID || event.GroupID == groupID {
				require.Equal(t, target, event.TenantID)
			}
			if event.GroupID == rootID && event.UserID == "" {
				require.True(t, owner.IsZero(), "global events must not inherit the worker's default tenant")
			}
			received = append(received, event)
			return nil
		},
		OnPurge: func(ctx context.Context, deletion iam.UserDeletion) error {
			owner, bound := tenancy.From(ctx)
			require.True(t, bound)
			require.Equal(t, target, owner)
			require.Equal(t, target, deletion.TenantID)
			require.Equal(t, userID, deletion.UserID)
			purges = append(purges, deletion)
			if retryPurge {
				return errors.New("retry this tenant's storage cleanup")
			}
			return nil
		},
	}
	e := newTestEngine(t, cfg, deps)
	ctx := t.Context()
	require.NoError(t, e.CreateTenant(ctx, iam.Tenant{ID: target}))
	actor := newUser(t, e, "lcactor")
	_, err := e.SetGroupRole(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(actor.ID), iam.RootPersona().OwnerRole())
	require.NoError(t, err)
	root, err := e.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	rootID = root.ID
	_, err = e.CreateGroupRole(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.NewGroupRole{Name: "global-reader", Permissions: []iam.Perm{cfg.Roles.Root.Users.Read}})
	require.NoError(t, err)
	owned := WithTenant(ctx, target)
	// The default A user is unrelated to the B account whose lifecycle follows.
	user, err := e.CreateUser(owned, iam.NewUser{Email: "target@example.test", Username: "lctarget"})
	require.NoError(t, err)
	userID = user.ID
	group, err := e.CreateGroup(owned, iam.NewGroup{Persona: app.Persona})
	require.NoError(t, err)
	groupID = group.ID
	require.NoError(t, e.PurgeGroup(owned, iam.GroupByID(groupID)))

	results, err := e.DeleteUsers(owned, iam.UserIdentity(actor.ID), []string{userID})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Err)
	var deletionID string
	require.NoError(t, e.pg.QueryRow(ctx, `SELECT id::text FROM account_deletions WHERE user_id=$1 AND state='deleted'`, userID).Scan(&deletionID))
	_, err = e.pg.Exec(ctx, `WITH expired AS (
		UPDATE users SET deleted_at=statement_timestamp()-interval '31 days' WHERE id=$1 RETURNING deleted_at
	) UPDATE account_deletions SET deleted_at=expired.deleted_at,purge_at=expired.deleted_at+interval '720 hours'
	FROM expired WHERE account_deletions.id=$2`, userID, deletionID)
	require.NoError(t, err)
	wrong := WithTenant(ctx, cfg.DefaultTenantID)
	sweep := &accountDeleteDueWorker{engine: e}
	require.NoError(t, sweep.Work(wrong, &river.Job[accountDeleteDueArgs]{Args: accountDeleteDueArgs{Schema: schema}}))
	var deliveryID int64
	require.NoError(t, e.pg.QueryRow(ctx, `SELECT id FROM account_deletion_deliveries WHERE deletion_id=$1 AND stage='hard'`, deletionID).Scan(&deliveryID))
	delivery := &accountDeliveryWorker{engine: e}
	job := &river.Job[accountDeliveryArgs]{Args: accountDeliveryArgs{Schema: schema, Issuer: cfg.Token.Issuer, DeliveryID: deliveryID}}
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, delivery.Work(wrong, job), &snooze)
	require.Len(t, purges, 1)

	// No target is carried in the job args. A new default-A worker must recover
	// B from the durable receipt rather than its configuration or caller context.
	require.NoError(t, e.Close(ctx))
	e = newTestEngine(t, cfg, deps)
	retryPurge = false
	delivery.engine, sweep.engine = e, e
	require.NoError(t, delivery.Work(wrong, job))
	require.Len(t, purges, 2)
	require.Equal(t, purges[0], purges[1])
	require.NoError(t, sweep.Work(wrong, &river.Job[accountDeleteDueArgs]{Args: accountDeleteDueArgs{Schema: schema}}))
	var exists bool
	require.NoError(t, e.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, userID).Scan(&exists))
	require.False(t, exists)
	var retained string
	require.NoError(t, e.pg.QueryRow(ctx, `SELECT tenant_id::text FROM account_deletions WHERE id=$1 AND state='purged'`, deletionID).Scan(&retained))
	require.Equal(t, target.String(), retained)
	rows, err := e.pg.Query(ctx, `SELECT id FROM account_events ORDER BY id`)
	require.NoError(t, err)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	worker := &accountEventWorker{engine: e}
	for _, id := range ids {
		require.NoError(t, worker.Work(wrong, &river.Job[accountEventArgs]{Args: accountEventArgs{Schema: schema, Issuer: cfg.Token.Issuer, Row: id}}))
	}
	foundDeleted, foundPurged, foundGroup, foundGlobal := false, false, false, false
	for _, event := range received {
		if event.UserID == userID && event.Kind == iam.EventUserDeleted {
			foundDeleted = true
			require.Equal(t, actor.ID, event.SubjectID)
			require.Equal(t, target, event.TenantID)
		}
		if event.UserID == userID && event.Kind == iam.EventUserPurged {
			foundPurged = true
			require.Equal(t, target, event.TenantID)
		}
		if event.GroupID == rootID && event.UserID == "" {
			foundGlobal = true
		}
		if event.GroupID == groupID && event.Kind == iam.EventGroupPurged {
			foundGroup = true
		}
	}
	require.True(t, foundDeleted)
	require.True(t, foundPurged)
	require.True(t, foundGroup)
	require.True(t, foundGlobal)
}
