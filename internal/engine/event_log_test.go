package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	pgmigrations "github.com/open-rails/authkit/internal/migrations/postgres"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
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
	var jobs, legacy int
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM public.river_job WHERE kind='authkit_account_event'").Scan(&jobs))
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM account_events").Scan(&legacy))
	require.Zero(t, jobs)
	require.Zero(t, legacy)
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
	bStarted, bDone := make(chan struct{}), make(chan error, 1)
	go func() {
		close(bStarted)
		err := e.appendEventLog(ctx, b, []iam.Event{two})
		if err == nil {
			err = b.Commit(ctx)
		}
		bDone <- err
	}()
	<-bStarted
	// B is allowed to attempt its commit first, but the per-scope lock keeps
	// its position behind A. A different tenant remains independently writable.
	other := eventLogTestEvent(iam.TenantID(uuid.New()), iam.EventUserRegistered)
	appendTestEvents(t, e, other)
	uncommitted, err := e.ListEvents(ctx, iam.EventQuery{After: first.NextCursor})
	require.NoError(t, err)
	require.Empty(t, uncommitted.Events)
	select {
	case err := <-bDone:
		t.Fatalf("later same-scope writer passed uncommitted predecessor: %v", err)
	default:
	}
	require.NoError(t, a.Commit(ctx))
	require.NoError(t, <-bDone)
	page, err := e.ListEvents(ctx, iam.EventQuery{After: uncommitted.NextCursor})
	require.NoError(t, err)
	require.Equal(t, []string{one.ID, two.ID}, eventIDs(page.Events))
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
	_, err = e.pg.Exec(t.Context(), "UPDATE event_log SET recorded_at=clock_timestamp()-interval '91 days'")
	require.NoError(t, err)
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
	page, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
	appendTestEvents(t, e, eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserRegistered))
	page, err = e.ListEvents(t.Context(), iam.EventQuery{After: page.NextCursor})
	require.NoError(t, err)
	_, err = e.pg.Exec(t.Context(), "UPDATE event_log SET event_id=gen_random_uuid()")
	require.NoError(t, err)
	_, err = e.ListEvents(t.Context(), iam.EventQuery{After: page.NextCursor})
	require.ErrorIs(t, err, iam.ErrEventCursorExpired, "restored alternate history must invalidate its boundary cursor")
}

func TestEventLogAppendPayloadMatchesCommittedEvent(t *testing.T) {
	e := eventLogTestEngine(t)
	event := eventLogTestEvent(testdb.DefaultTenantID, iam.EventUserEmailChanged)
	event.Previous, event.Current = "before@example.test", "after@example.test"
	appendTestEvents(t, e, event)
	page, err := e.ListEvents(t.Context(), iam.EventQuery{})
	require.NoError(t, err)
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
	e := eventLogTestEngine(t)
	ctx := t.Context()
	_, err := e.pg.Exec(ctx, "DROP TABLE event_log,event_log_scopes,event_log_instance")
	require.NoError(t, err)
	id := uuid.NewString()
	_, err = e.pg.Exec(ctx, `INSERT INTO account_events(issuer,stream,event_id,kind,previous_value,current_value)
VALUES('issuer-a','group:root',$1,'group.created','before','after'),
      ('issuer-b','group:root',$1,'group.created','before','after')`, id)
	require.NoError(t, err)
	sql, err := pgmigrations.FS.ReadFile("0022_event_log.up.sql")
	require.NoError(t, err)
	_, err = e.pg.Exec(ctx, string(sql))
	require.NoError(t, err)
	page, err := e.ListEvents(ctx, iam.EventQuery{Authority: true})
	require.NoError(t, err)
	require.Equal(t, []string{id}, eventIDs(page.Events))
	require.Equal(t, "after", page.Events[0].Current)
	var pending int
	require.NoError(t, e.pg.QueryRow(ctx, "SELECT count(*) FROM account_events").Scan(&pending))
	require.Equal(t, 2, pending, "the migration must not drop existing delivery obligations")
}

func TestEventLogPrunesBoundedBatches(t *testing.T) {
	e := eventLogTestEngine(t)
	ctx := t.Context()
	scope := testdb.DefaultTenantID.String()
	_, err := e.pg.Exec(ctx, "INSERT INTO event_log_scopes(scope,position) VALUES($1,5001)", scope)
	require.NoError(t, err)
	_, err = e.pg.Exec(ctx, `INSERT INTO event_log(scope,position,event_id,kind,recorded_at,payload)
SELECT $1,n,gen_random_uuid(),'user.registered',clock_timestamp()-interval '91 days','{}'::jsonb
FROM generate_series(1,5001) n`, scope)
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
