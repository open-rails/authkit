package embedded

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/testdb"
)

// #325: the session GC removes revoked and expired sessions (history
// cascading) in bounded batches — 2*batch+1 dead rows take exactly three
// batches — and never touches live sessions.
func TestGCDeadSessionsBatches(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pg.Pool))
	user, err := svc.CreateUser(ctx, "gc@example.com", "gc-user")
	if err != nil {
		t.Fatal(err)
	}

	const batch = int64(4)
	insert := func(i int, expiresAt time.Time, revoked bool) {
		t.Helper()
		var revokedAt *time.Time
		if revoked {
			r := time.Now().Add(-time.Hour)
			revokedAt = &r
		}
		var id string
		if err := pg.Pool.QueryRow(ctx,
			`INSERT INTO profiles.refresh_sessions (user_id, issuer, current_token_hash, expires_at, revoked_at)
			 VALUES ($1::uuid, 'https://test', $2, $3, $4) RETURNING id::text`,
			user.ID, []byte(fmt.Sprintf("tok-%d", i)), expiresAt, revokedAt).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Pool.Exec(ctx,
			`INSERT INTO profiles.refresh_token_history (token_hash, session_id) VALUES ($1, $2::uuid)`,
			[]byte(fmt.Sprintf("hist-%d", i)), id); err != nil {
			t.Fatal(err)
		}
	}
	dead := int(2*batch + 1)
	for i := 0; i < dead; i++ {
		if i%2 == 0 {
			insert(i, time.Now().Add(24*time.Hour), true) // revoked, not expired
		} else {
			insert(i, time.Now().Add(-time.Minute), false) // expired, not revoked
		}
	}
	const live = 3
	for i := 0; i < live; i++ {
		insert(100+i, time.Now().Add(24*time.Hour), false)
	}

	batches, err := svc.gcDeadSessions(ctx, batch)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if batches != 3 {
		t.Fatalf("batches=%d, want 3 for %d dead rows at batch %d", batches, dead, batch)
	}
	var sessions, history, deadLeft int
	if err := pg.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM profiles.refresh_sessions),
		(SELECT count(*) FROM profiles.refresh_token_history),
		(SELECT count(*) FROM profiles.refresh_sessions WHERE revoked_at IS NOT NULL OR expires_at <= now())`).
		Scan(&sessions, &history, &deadLeft); err != nil {
		t.Fatal(err)
	}
	if sessions != live || history != live || deadLeft != 0 {
		t.Fatalf("sessions=%d history=%d dead=%d, want %d/%d/0", sessions, history, deadLeft, live, live)
	}
	if batches, err := svc.gcDeadSessions(ctx, batch); err != nil || batches != 1 {
		t.Fatalf("idle sweep batches=%d err=%v, want one short batch", batches, err)
	}
}
