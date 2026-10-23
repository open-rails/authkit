package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/cursor"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/migratekit"
	"github.com/stretchr/testify/require"
	"strings"
)

func eventLogTestEngine(t *testing.T) *Engine {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	return newTestEngine(t, maintenanceConfig(), config.Deps{Postgres: pg.Pool})
}

func eventLogTestEvent(tenant iam.TenantID, kind iam.EventKind) iam.Event {
	return iam.Event{ID: uuid.NewString(), Version: 1, TenantID: tenant, Kind: kind, OccurredAt: time.Now().UTC()}
}

func appendTestEvents(t *testing.T, e *Engine, events ...iam.Event) {
	t.Helper()
	tx, err := e.pg.Begin(t.Context())
	require.NoError(t, err)
	defer tx.Rollback(t.Context())
	require.NoError(t, e.appendEventLog(t.Context(), tx, events))
	require.NoError(t, tx.Commit(t.Context()))
}

func TestEventLogRecordsWithoutSubscriberOrDeliveryJob(t *testing.T) {
	e := eventLogTestEngine(t)
	u, err := e.CreateUser(t.Context(), iam.NewUser{Username: "eventreader"})
	require.NoError(t, err)
	page, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	require.Equal(t, iam.EventUserRegistered, page.Events[0].Kind)
	require.Equal(t, u.ID, page.Events[0].UserID)
	require.Equal(t, 1, page.Events[0].Version)
	require.NotEmpty(t, page.NextCursor)
	require.Equal(t, int64(90*24*60*60), page.RetentionSeconds)
	var jobs int
	var legacy *string
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job WHERE kind='authkit_account_event'").Scan(&jobs))
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT to_regclass('profiles.account_events')::text").Scan(&legacy))
	require.Zero(t, jobs)
	require.Nil(t, legacy)
}

func TestEventLogRollbackAndCommitOrder(t *testing.T) {
	e := eventLogTestEngine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	first, err := e.ListEvents(ctx, iam.EventQuery{})
	require.NoError(t, err)
	a, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	defer a.Rollback(ctx)
	one := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)
	require.NoError(t, e.appendEventLog(ctx, a, []iam.Event{one}))
	b, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	defer b.Rollback(ctx)
	two := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserUsernameChanged)
	require.NoError(t, e.appendEventLog(ctx, b, []iam.Event{two}))
	require.NoError(t, b.Commit(ctx))
	other := eventLogTestEvent(iam.TenantID(uuid.New()), iam.EventUserRegistered)
	appendTestEvents(t, e, other)
	firstCommitted, err := e.ListEvents(ctx, iam.EventQuery{After: first.NextCursor})
	require.NoError(t, err)
	require.Equal(t, []string{two.ID}, eventIDs(firstCommitted.Events))
	require.NoError(t, a.Commit(ctx))
	page, err := e.ListEvents(ctx, iam.EventQuery{After: firstCommitted.NextCursor})
	require.NoError(t, err)
	require.Equal(t, []string{one.ID}, eventIDs(page.Events), "late transaction must remain visible after earlier committed cursor")
	rollback, err := e.pg.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, e.appendEventLog(ctx, rollback, []iam.Event{eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserDeleted)}))
	require.NoError(t, rollback.Rollback(ctx))
	three := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRestored)
	appendTestEvents(t, e, three)
	page, err = e.ListEvents(ctx, iam.EventQuery{After: page.NextCursor})
	require.NoError(t, err)
	require.Equal(t, []string{three.ID}, eventIDs(page.Events))
	var head, rows int64
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT position FROM event_log_scopes WHERE scope=$1", testdb.DefaultTenantID.String()).Scan(&head))
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT count(*) FROM event_log WHERE scope=$1", testdb.DefaultTenantID.String()).Scan(&rows))
	require.Equal(t, rows, head, "rollback must not leave an allocated hole")
}

func eventIDs(events []iam.Event) []string {
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.ID)
	}
	return ids
}

func TestEventLogIndependentReadersFilteringAndScope(t *testing.T) {
	e := eventLogTestEngine(t)
	a, b, c := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered), eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserDeleted), eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRestored)
	appendTestEvents(t, e, a, b, c, eventLogTestEvent(iam.TenantID{}, iam.EventGroupCreated))
	first, err := e.ListEvents(t.Context(), iam.EventQuery{Limit: 1})
	require.NoError(t, err)
	require.True(t, first.HasMore)
	require.Equal(t, []string{a.ID}, eventIDs(first.Events))
	for range 2 {
		replay, err := e.ListEvents(t.Context(), iam.EventQuery{After: first.NextCursor})
		require.NoError(t, err)
		require.Equal(t, []string{b.ID, c.ID}, eventIDs(replay.Events), "two readers and failed processing may replay independently")
	}
	filtered, err := e.ListEvents(t.Context(), iam.EventQuery{Kinds: []iam.EventKind{iam.EventUserDeleted}})
	require.NoError(t, err)
	require.Equal(t, []string{b.ID}, eventIDs(filtered.Events))
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: filtered.NextCursor})
	require.Error(t, err, "a cursor cannot silently change filters")
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: first.NextCursor, Authority: true})
	require.Error(t, err, "a tenant cursor cannot be replayed against authority scope")
	authority, err := e.ListEvents(t.Context(), iam.EventQuery{Authority: true})
	require.NoError(t, err)
	require.Len(t, authority.Events, 1)
	require.True(t, authority.Events[0].TenantID.IsZero())
	for _, limit := range []int{-1, 501} {
		_, err = e.ListEvents(t.Context(), iam.EventQuery{Limit: limit})
		require.Error(t, err)
	}
}

func TestEventLogExpiryPruningAndReset(t *testing.T) {
	e := eventLogTestEngine(t)
	before, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	a := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)
	appendTestEvents(t, e, a)
	read, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	future := time.Now().Add(91 * 24 * time.Hour)
	e.SetClock(func() time.Time { return future })
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: before.NextCursor})
	require.ErrorIs(t, err, iam.ErrEventCursorExpired)
	require.NoError(t, e.pruneEventLog(t.Context()))
	var rows int
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM event_log").Scan(&rows))
	require.Zero(t, rows)
	// A cursor exactly at the retired head loses no events and remains usable.
	empty, err := e.ListEvents(t.Context(), iam.EventQuery{After: read.NextCursor})
	require.NoError(t, err)
	require.Empty(t, empty.Events)
	_, err = e.pg.Exec(t.Context(), "UPDATE event_log_instance SET epoch=gen_random_uuid()")
	require.NoError(t, err)
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: empty.NextCursor})
	require.ErrorIs(t, err, iam.ErrEventCursorExpired)
	e.SetClock(time.Now)
	page, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	appendTestEvents(t, e, eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered))
	page, err = e.ListEvents(t.Context(), iam.EventQuery{After: page.NextCursor})
	require.NoError(t, err)
	var wrong eventLogCursor
	require.NoError(t, cursor.Decode(page.NextCursor, &wrong))
	wrong.EventID = uuid.NewString()
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: cursor.Encode(wrong)})
	require.ErrorIs(t, err, iam.ErrEventCursorExpired, "restored alternate history must invalidate its boundary cursor")
}

func TestEventLogAppendPayloadMatchesCommittedEvent(t *testing.T) {
	e := eventLogTestEngine(t)
	event := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserEmailChanged)
	event.Previous, event.Current = "before@example.test", "after@example.test"
	appendTestEvents(t, e, event)
	page, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	require.False(t, page.Events[0].RecordedAt.IsZero())
	event.RecordedAt = page.Events[0].RecordedAt
	a, err := json.Marshal(event)
	require.NoError(t, err)
	b, err := json.Marshal(page.Events[0])
	require.NoError(t, err)
	require.JSONEq(t, string(a), string(b))
}

func TestEventLogHTTPRequiresCurrentScopedPermission(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig()
	cfg.Roles = config.NewRoles()
	reader := cfg.Roles.Tenant.Role("event-reader", cfg.Roles.Tenant.Users.Read)
	rootReader := cfg.Roles.Root.Role("event-reader", cfg.Roles.Root.Users.Read)
	f := newAccountFlow(t, pg.Pool, cfg, config.Deps{})
	u := newUser(t, f.engine, "eventhttp")
	token := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *u.Email, "password": testPassword})).tokens().AccessToken
	f.expect(http.StatusUnauthorized, f.request(http.MethodGet, "/events", "", nil))
	f.expect(http.StatusForbidden, f.request(http.MethodGet, "/events", token, nil))
	_, err := f.engine.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.GroupByID(testdb.DefaultTenantID.String()), iam.UserSubject(u.ID), reader)
	require.NoError(t, err)
	page := f.expect(http.StatusOK, f.request(http.MethodGet, "/events?limit=1", token, nil))
	var listed iam.EventPage
	require.NoError(t, json.Unmarshal([]byte(page.raw), &listed))
	require.NotEmpty(t, listed.NextCursor)
	f.expect(http.StatusForbidden, f.request(http.MethodGet, "/events?authority=true", token, nil))
	require.NoError(t, f.engine.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.GroupByID(testdb.DefaultTenantID.String()), iam.UserSubject(u.ID)))
	f.expect(http.StatusForbidden, f.request(http.MethodGet, "/events", token, nil))
	_, err = f.engine.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(u.ID), rootReader)
	require.NoError(t, err)
	f.expect(http.StatusOK, f.request(http.MethodGet, "/events?authority=true", token, nil))
	f.expect(http.StatusBadRequest, f.request(http.MethodGet, "/events?limit=0", token, nil))
}

func TestEventLogMigrationKeepsOneCopyOfPendingDeliveries(t *testing.T) {
	pg := testdb.EmptyScratchPostgres(t)
	ctx := t.Context()
	all, err := migratekit.LoadFromFS(pgmigrations.FS)
	require.NoError(t, err)
	split := 0
	for i, m := range all {
		if strings.HasPrefix(m.Name, "0022_") {
			split = i
			break
		}
	}
	require.Positive(t, split)
	migrator, err := migratekit.NewPostgresFromPGXPool(pg.Pool, "authkit")
	require.NoError(t, err)
	defer migrator.Close()
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(ctx, all[:split]))
	id := uuid.NewString()
	_, err = pg.Pool.Exec(ctx, `INSERT INTO account_events(issuer,stream,event_id,kind,previous_value,current_value)
VALUES('issuer-a','group:root',$1,'group.created','before','after'),
      ('issuer-b','group:root',$1,'group.created','before','after')`, id)
	require.NoError(t, err)
	require.NoError(t, migrator.WithSchema("profiles").ApplyMigrations(ctx, all[split:]))
	cfg := maintenanceConfig()
	cfg.DefaultTenantID = iam.TenantID{} // This migration fixture contains authority events, no tenant directory.
	e := newTestEngine(t, cfg, config.Deps{Postgres: pg.Pool})
	page, err := e.ListEvents(ctx, iam.EventQuery{Authority: true})
	require.NoError(t, err)
	require.Equal(t, []string{id}, eventIDs(page.Events))
	require.Equal(t, "after", page.Events[0].Current)
	var legacy *string
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT to_regclass('profiles.account_events')::text").Scan(&legacy))
	require.Nil(t, legacy, "legacy per-issuer event copies are retired after the log copy")
}

func TestEventLogPrunesBoundedBatches(t *testing.T) {
	e := eventLogTestEngine(t)
	ctx := t.Context()
	scope := testdb.DefaultTenantID.String()
	_, err := e.pg.Exec(ctx, "INSERT INTO eventlog_streams(source,scope,position) VALUES('authkit',$1,5001)", scope)
	require.NoError(t, err)
	_, err = e.pg.Exec(ctx, `INSERT INTO eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,occurred_at,recorded_at,subject_type,subject_id,data)
SELECT 'authkit',$1,n,id,id,'authkit','user.registered',1,clock_timestamp()-interval '91 days',clock_timestamp()-interval '91 days','','','{}'::jsonb
FROM (SELECT n,gen_random_uuid()::text AS id FROM generate_series(1,5001) n) seed`, scope)
	require.NoError(t, err)
	require.NoError(t, e.pruneEventLog(ctx))
	var count, floor int64
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT count(*) FROM event_log").Scan(&count))
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT retained_after FROM event_log_scopes WHERE scope=$1", scope).Scan(&floor))
	require.Equal(t, int64(1), count)
	require.Equal(t, int64(5000), floor)
	require.NoError(t, e.pruneEventLog(ctx))
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT count(*) FROM event_log").Scan(&count))
	require.Zero(t, count)
}

func TestEventLogLegacyFloorAndNonmonotonicRetention(t *testing.T) {
	e := eventLogTestEngine(t)
	first := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)
	middle := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserEmailChanged)
	last := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)
	now := time.Now().UTC()
	e.SetClock(func() time.Time { return now })
	seedStoredEvents(t, e, []iam.Event{first, middle, last}, []time.Time{now.Add(-89 * 24 * time.Hour), now.Add(-91 * 24 * time.Hour), now})
	page, err := e.ListEvents(t.Context(), iam.EventQuery{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, first.ID, page.Events[0].ID)
	// Imported nonmonotonic history preserves younger rows but cannot recover
	// individually expired facts. This is the existing retained-only contract.
	retained, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	require.Equal(t, []string{first.ID, last.ID}, []string{retained.Events[0].ID, retained.Events[1].ID})
	require.NoError(t, e.pruneEventLog(t.Context()))
	var count int
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM event_log").Scan(&count))
	require.Equal(t, 3, count, "only an expired prefix can be pruned")
	// Once the prefix expires, its historical cursor still resumes at the floor.
	e.SetClock(func() time.Time { return now.Add(2 * 24 * time.Hour) })
	require.NoError(t, e.pruneEventLog(t.Context()))
	var old eventLogCursor
	require.NoError(t, cursor.Decode(page.NextCursor, &old))
	old.Position = 2 // the now-pruned prefix endpoint has no retained boundary ID
	old.EventID = middle.ID
	resumed, err := e.ListEvents(t.Context(), iam.EventQuery{After: cursor.Encode(old)})
	require.NoError(t, err)
	require.Len(t, resumed.Events, 1)
	require.Equal(t, last.ID, resumed.Events[0].ID)
}

func TestEventLogLegacyLargeFilterAndWhitespaceCursor(t *testing.T) {
	e := eventLogTestEngine(t)
	event := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered)
	appendTestEvents(t, e, event)
	kinds := make([]iam.EventKind, 100)
	for i := range kinds {
		kinds[i] = iam.EventKind(fmt.Sprintf("future.%03d", i))
	}
	kinds[0] = iam.EventUserRegistered
	page, err := e.ListEvents(t.Context(), iam.EventQuery{Kinds: kinds})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	// A pre-adoption cursor used this same v/e/s/k/p/i envelope and full filter.
	var old eventLogCursor
	require.NoError(t, cursor.Decode(page.NextCursor, &old))
	require.Len(t, old.Kinds, 100)
	next, err := e.ListEvents(t.Context(), iam.EventQuery{Kinds: kinds, After: cursor.Encode(old)})
	require.NoError(t, err)
	require.Empty(t, next.Events)
	spaced := []iam.EventKind{" user.registered "}
	page, err = e.ListEvents(t.Context(), iam.EventQuery{Kinds: spaced})
	require.NoError(t, err)
	require.Empty(t, page.Events)
	require.NoError(t, cursor.Decode(page.NextCursor, &old))
	require.Equal(t, []string{" user.registered "}, old.Kinds)
	_, err = e.ListEvents(t.Context(), iam.EventQuery{Kinds: spaced, After: cursor.Encode(old)})
	require.NoError(t, err)
	// The new Types API retains common trim/sort normalization.
	page, err = e.ListEvents(t.Context(), iam.EventQuery{Types: []string{" user.registered "}})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
}

// seedStoredEvents constructs imported history without mutating immutable facts.
func seedStoredEvents(t *testing.T, e *Engine, events []iam.Event, recorded []time.Time) {
	t.Helper()
	scope := eventLogScope(events[0].TenantID)
	_, err := e.pg.Exec(t.Context(), `INSERT INTO eventlog_streams(source,scope) VALUES('authkit',$1) ON CONFLICT DO NOTHING`, scope)
	require.NoError(t, err)
	for i, event := range events {
		payload, err := json.Marshal(event)
		require.NoError(t, err)
		_, err = e.pg.Exec(t.Context(), `INSERT INTO eventlog_events(source,scope,position,id,boundary,event_source,event_type,version,occurred_at,recorded_at,subject_type,subject_id,data) VALUES('authkit',$1,$2,$3,$3,'authkit',$4,$5,$6,$7,'','',$8)`, scope, i+1, event.ID, event.Kind, event.Version, event.OccurredAt, recorded[i], payload)
		require.NoError(t, err)
	}
	_, err = e.pg.Exec(t.Context(), `UPDATE eventlog_streams SET position=$2,head_id=$3,recorded_at=(SELECT max(recorded_at) FROM eventlog_events WHERE source='authkit' AND scope=$1) WHERE source='authkit' AND scope=$1`, scope, len(events), events[len(events)-1].ID)
	require.NoError(t, err)
}
