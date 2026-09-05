package authcore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// #258: N concurrent cold boots on a database with no root group must all
// succeed and agree on ONE root row — the losers of the singleton-index race
// adopt the winner's row instead of surfacing the unique violation.
func TestEnsureRootGroupConcurrentColdBoots(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	const n = 16
	svcs := make([]*Service, n)
	for i := range svcs {
		svcs[i] = mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))
	}

	start := make(chan struct{})
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			ids[i], errs[i] = svcs[i].EnsureRootGroup(ctx)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("boot %d: %v", i, errs[i])
		}
		if ids[i] == "" || ids[i] != ids[0] {
			t.Fatalf("boot %d returned id %q, boot 0 returned %q", i, ids[i], ids[0])
		}
	}
	var rows int
	if err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.permission_groups WHERE persona = 'root'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("root rows=%d, want 1", rows)
	}
}

// #258 (deterministic loser path): the winner's insert is held uncommitted so
// the loser is guaranteed to read not-found, block on the singleton index, hit
// the unique violation after the commit, and adopt the winner's id.
func TestEnsureRootGroupAdoptsConcurrentWinner(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))

	tx, err := pg.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var winner string
	if err := tx.QueryRow(ctx, `INSERT INTO profiles.permission_groups (persona) VALUES ('root') RETURNING id::text`).Scan(&winner); err != nil {
		t.Fatalf("winner insert: %v", err)
	}

	done := make(chan struct{})
	var loser string
	var loserErr error
	go func() {
		defer close(done)
		loser, loserErr = svc.EnsureRootGroup(ctx)
	}()
	deadline := time.After(10 * time.Second)
	for {
		var waiting int
		if err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%permission_groups%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("loser never blocked on the singleton index")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	<-done
	if loserErr != nil {
		t.Fatalf("loser must adopt the winner, got %v", loserErr)
	}
	if loser != winner {
		t.Fatalf("loser id=%s, winner id=%s", loser, winner)
	}
}
