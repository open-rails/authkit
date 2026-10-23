package engine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/cursor"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	sharedpg "github.com/open-rails/helpers/eventlog/postgres"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
)

func TestEventLogSharedSchemaIsCanonical(t *testing.T) {
	b, err := os.ReadFile("../migrations/postgres/0025_shared_eventlog_contract.up.sql")
	require.NoError(t, err)
	_, tail, ok := strings.Cut(string(b), "-- BEGIN helpers/eventlog/postgres schema v1 (verbatim; checked by test)\n")
	require.True(t, ok)
	got, _, ok := strings.Cut(tail, "-- END helpers/eventlog/postgres schema v1")
	require.True(t, ok)
	want, err := sharedpg.MigrationSQL("__authkit_eventlog_schema__", 1)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestEventLogSharedStorageMigrationPreservesHistory(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx := t.Context()
	chain, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	split := -1
	for i, m := range chain {
		if strings.HasPrefix(m.Name, "0025_") {
			split = i
		}
	}
	require.Positive(t, split)
	migrator, err := migratekit.NewPostgresFromPGXPool(pg.Pool, "authkit")
	require.NoError(t, err)
	defer migrator.Close()
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(ctx, chain[:split]))
	var epoch string
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT epoch::text FROM event_log_instance`).Scan(&epoch))
	scope := testdb.DefaultTenantID.String()
	floorID := uuid.NewString()
	_, err = pg.Pool.Exec(ctx, `INSERT INTO event_log_scopes(scope,position,retained_after) VALUES($1,4,1)`, scope)
	require.NoError(t, err)
	now := time.Now().UTC()
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	times := []time.Time{now.Add(-time.Hour), now.Add(-91 * 24 * time.Hour), now.Add(-time.Minute)}
	var raw []byte
	for i, id := range ids {
		payload := map[string]any{"version": 1, "id": id, "kind": "user.registered", "tenant_id": scope, "occurred_at": times[i], "future": map[string]any{"kept": "raw"}}
		raw, err = json.Marshal(payload)
		require.NoError(t, err)
		_, err = pg.Pool.Exec(ctx, `INSERT INTO event_log(scope,position,event_id,kind,recorded_at,payload) VALUES($1,$2,$3,'user.registered',$4,$5)`, scope, i+2, id, times[i], raw)
		require.NoError(t, err)
	}
	afterFloor := cursor.Encode(eventLogCursor{Version: 1, Epoch: epoch, Scope: scope, Position: 1, EventID: floorID})
	emptyAuthority := cursor.Encode(eventLogCursor{Version: 1, Epoch: epoch, Scope: "authority"})
	// A cancelled migration leaves the original schema and history intact.
	tx, err := pg.Pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, chain[split].Content)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	var oldCount int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM event_log`).Scan(&oldCount))
	require.Equal(t, 3, oldCount)
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(ctx, chain[split:]))
	e := newTestEngine(t, maintenanceConfig(), config.Deps{Postgres: pg.Pool})
	got, err := e.ListEvents(ctx, iam.EventQuery{After: afterFloor})
	require.NoError(t, err)
	require.Equal(t, []string{ids[0], ids[2]}, eventIDs(got.Events), "retained-only semantics preserve younger facts and exclude already-expired imported holes")
	require.WithinDuration(t, times[0], got.Events[0].RecordedAt, time.Microsecond)
	var rawPreserved bool
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT data=$1::jsonb FROM eventlog_events WHERE source='authkit' AND id=$2`, raw, ids[2]).Scan(&rawPreserved))
	require.True(t, rawPreserved)
	late := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserDeleted)
	appendTestEvents(t, e, late)
	next, err := e.ListEvents(ctx, iam.EventQuery{After: got.NextCursor})
	require.NoError(t, err)
	require.Equal(t, []string{late.ID}, eventIDs(next.Events))
	authority := eventLogTestEvent(iam.TenantID{}, iam.EventGroupCreated)
	appendTestEvents(t, e, authority)
	authorityPage, err := e.ListEvents(ctx, iam.EventQuery{Authority: true, After: emptyAuthority})
	require.NoError(t, err)
	require.Equal(t, []string{authority.ID}, eventIDs(authorityPage.Events))
}

func TestEventLogOppositeScopeAppendCalls(t *testing.T) {
	e := eventLogTestEngine(t)
	ctx := t.Context()
	a, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	defer a.Rollback(ctx)
	b, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	defer b.Rollback(ctx)
	require.NoError(t, e.appendEventLog(ctx, a, []iam.Event{eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)}))
	require.NoError(t, e.appendEventLog(ctx, b, []iam.Event{eventLogTestEvent(iam.TenantID{}, iam.EventGroupCreated)}))
	require.NoError(t, e.appendEventLog(ctx, a, []iam.Event{eventLogTestEvent(iam.TenantID{}, iam.EventGroupCreated)}))
	require.NoError(t, e.appendEventLog(ctx, b, []iam.Event{eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)}))
	done := make(chan error, 2)
	go func() { done <- a.Commit(ctx) }()
	go func() { done <- b.Commit(ctx) }()
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	for _, authority := range []bool{false, true} {
		page, err := e.ListEvents(ctx, iam.EventQuery{Authority: authority})
		require.NoError(t, err)
		require.Len(t, page.Events, 2)
	}
}
