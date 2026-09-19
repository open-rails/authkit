package embedded

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type erasureLockGate struct {
	entered, release chan struct{}
	once             sync.Once
}
type erasureLockQuery struct{}

func (g *erasureLockGate) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, erasureLockQuery{}, strings.Contains(d.SQL, "-- name: ErasureObligationLock"))
}
func (g *erasureLockGate) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if yes, _ := ctx.Value(erasureLockQuery{}).(bool); yes && d.Err == nil {
		g.once.Do(func() {
			close(g.entered)
			select {
			case <-g.release:
			case <-ctx.Done():
			}
		})
	}
}

func TestErasureRepeatedDeletionSerializesWithAcknowledgement(t *testing.T) {
	for _, hard := range []bool{false, true} {
		name := "soft"
		if hard {
			name = "hard"
		}
		t.Run(name, func(t *testing.T) { testErasureRepeatedDeletion(t, hard, false) })
	}
	t.Run("new-required-issuer", func(t *testing.T) { testErasureRepeatedDeletion(t, false, true) })
}

func testErasureRepeatedDeletion(t *testing.T, hard, addIssuer bool) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const issuer = "https://erasure-race.test"
	site := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: issuer}}, Keyset{}, WithPostgres(pg.Pool))
	user, err := site.CreateUser(ctx, "erase-race@example.test", "erase-race")
	require.NoError(t, err)
	require.NoError(t, site.SoftDeleteUser(ctx, user.ID))
	const newIssuer = "https://erasure-new-site.test"
	if addIssuer {
		site = mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: issuer, AccountIssuers: []string{newIssuer}}}, Keyset{}, WithPostgres(pg.Pool))
	}
	gate := &erasureLockGate{entered: make(chan struct{}), release: make(chan struct{})}
	cfg, err := pgxpool.ParseConfig(pg.URL)
	require.NoError(t, err)
	cfg.ConnConfig.Tracer = gate
	ackPool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer ackPool.Close()
	var release sync.Once
	unblock := func() { release.Do(func() { close(gate.release) }) }
	defer unblock()
	ackSite := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: issuer}}, Keyset{}, WithPostgres(ackPool))
	ackDone := make(chan error, 1)
	go func() { ackDone <- ackSite.AcknowledgeErasure(ctx, issuer, user.ID) }()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// ACK owns the obligation row but has not changed its child row yet.
	deleteDone := make(chan error, 1)
	go func() {
		if hard {
			deleteDone <- site.HardDeleteUser(ctx, user.ID)
		} else {
			deleteDone <- site.SoftDeleteUser(ctx, user.ID)
		}
	}()
	var waitingSQL string
	require.Eventually(t, func() bool {
		err := pg.Pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%account_erasure_obligations%' LIMIT 1`).Scan(&waitingSQL)
		return err == nil
	}, 10*time.Second, 10*time.Millisecond)
	t.Logf("repeat deletion blocked on %s", strings.Split(waitingSQL, "\n")[0])
	unblock()
	require.NoError(t, <-ackDone)
	require.NoError(t, <-deleteDone)
	if hard {
		var remaining int
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM account_erasure_obligations WHERE user_id=$1::uuid`, user.ID).Scan(&remaining))
		require.Zero(t, remaining, "fully acknowledged hard deletion must close its obligation")
		return
	}
	var pending, unacked int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT pending_sites,(SELECT count(*) FROM account_erasure_acknowledgements WHERE user_id=$1::uuid AND acknowledged_at IS NULL) FROM account_erasure_obligations WHERE user_id=$1::uuid`, user.ID).Scan(&pending, &unacked))
	require.Equal(t, unacked, pending, "readiness must match committed acknowledgement state")
	if addIssuer {
		require.Equal(t, 1, pending, "the newly required site must remain pending")
		require.NoError(t, site.AcknowledgeErasure(ctx, newIssuer, user.ID))
	} else {
		require.Zero(t, pending)
	}
	backlog, err := site.ErasureBacklog(ctx)
	require.NoError(t, err)
	require.Empty(t, backlog)
	purge, err := site.ListUsersDeletedBefore(ctx, time.Now().Add(time.Second), 10)
	require.NoError(t, err)
	require.Equal(t, []string{user.ID}, purge, "fully acknowledged deletion must remain purgeable")
}
