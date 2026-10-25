package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/authkit/notify"
)

func database(t *testing.T) (*Store, *pgxpool.Pool, string) {
	t.Helper()
	url := os.Getenv("NOTIFY_TEST_DATABASE_URL")
	if url == "" {
		url = os.Getenv("RIVER_TEST_DATABASE_URL")
	}
	if url == "" {
		t.Skip("set NOTIFY_TEST_DATABASE_URL for PostgreSQL inbox tests")
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notify_test_" + strings.ToLower(rand.Text())
	if _, err = pool.Exec(t.Context(), `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, `DROP SCHEMA `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
		pool.Close()
		if err != nil {
			t.Error(err)
		}
	})
	if err = Migrate(t.Context(), pool, schema); err != nil {
		t.Fatal(err)
	}
	// Hosts using database/sql share the same migration ledger and tables.
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = MigrateDB(t.Context(), db, schema); err != nil {
		t.Fatal(err)
	}
	s, err := New(pool, Config{Schema: schema, Scope: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	return s, pool, schema
}

func input(id string) notify.Input {
	return notify.Input{Recipient: notify.Recipient{Audience: notify.AudienceUser, ID: "alice"}, Origin: notify.Origin{System: "billing.example", Scope: "merchant-1", ID: id}, Kind: "payment.failed", Data: []byte(`{"amount":"9007199254740993","future":{"field":true}}`), CreatedAt: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), Status: notify.StatusOpen}
}

func TestPublishRetryReadAndResolutionAreIndependent(t *testing.T) {
	s, _, _ := database(t)
	ctx := t.Context()
	in := input("event-1")
	n, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetRead(ctx, in.Recipient, n.ID, true); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n = page.Items[0]
	if n.ReadAt == nil || n.Status != notify.StatusOpen || n.ResolvedAt != nil {
		t.Fatalf("reading resolved work: %+v", n)
	}
	resolved, err := s.Transition(ctx, in.Recipient, n.ID, n.Revision, notify.StatusResolved)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ReadAt == nil || resolved.ResolvedAt == nil {
		t.Fatalf("missing separate state: %+v", resolved)
	}
	if _, err = s.Transition(ctx, in.Recipient, n.ID, n.Revision, notify.StatusDismissed); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("stale transition: %v", err)
	}
	in.Data = []byte(`{"changed":true}`)
	duplicate, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate.ID != n.ID || duplicate.Status != notify.StatusResolved || !strings.Contains(string(duplicate.Data), "9007199254740993") {
		t.Fatalf("retry reset state/content: %+v", duplicate)
	}
	if _, err = s.SetRead(ctx, in.Recipient, n.ID, false); err != nil {
		t.Fatal(err)
	}
	page, _ = s.List(ctx, in.Recipient, notify.ListOptions{UnreadOnly: true})
	if len(page.Items) != 1 || page.Items[0].Status != notify.StatusResolved {
		t.Fatalf("unread changed workflow: %+v", page)
	}
	in = input("notice")
	in.Status = notify.StatusNotice
	in.ActionRequested = true // Historical request, without a tracked workflow.
	n, err = s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !n.ActionRequested || n.Status != notify.StatusNotice {
		t.Fatalf("history became open work: %+v", n)
	}
	if _, err = s.Transition(ctx, in.Recipient, n.ID, n.Revision, notify.StatusResolved); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("general notice gained workflow: %v", err)
	}
}

func TestConcurrentPublishAndTransactionRollback(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	in := input("concurrent")
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			n, err := s.Publish(ctx, in)
			if err != nil {
				errs <- err
				return
			}
			ids <- n.ID
		})
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Errorf("duplicate ids %s %s", first, id)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PublishTx(ctx, tx, input("rolled-back")); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("rollback visible: %+v %v", page, err)
	}
}

func TestScopeAudienceRecipientIsolationAndPagination(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	in := input("a")
	first, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Origin.ID = "b"
	if _, err = s.Publish(ctx, in); err != nil {
		t.Fatal(err)
	}
	other, err := New(pool, Config{Schema: schema, Scope: "tenant-b"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []*Store{s, other} {
		x := input("same-source")
		x.Recipient.ID = "bob"
		if _, err = target.Publish(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	op := input("operator")
	op.Recipient = notify.Recipient{Audience: notify.AudienceOperator, ID: "alice"}
	if _, err = s.Publish(ctx, op); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, in.Recipient, notify.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	next, err := s.List(ctx, in.Recipient, notify.ListOptions{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == page.Items[0].ID || next.NextCursor != "" {
		t.Fatalf("second page: %+v %v", next, err)
	}
	if _, err = other.List(ctx, in.Recipient, notify.ListOptions{Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("cross scope cursor: %v", err)
	}
	if _, err = s.List(ctx, op.Recipient, notify.ListOptions{Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("cross audience cursor: %v", err)
	}
	if _, err = other.SetRead(ctx, in.Recipient, first.ID, true); !errors.Is(err, notify.ErrNotFound) {
		t.Fatalf("foreign scope mutation: %v", err)
	}
	if _, err = s.SetRead(ctx, op.Recipient, first.ID, true); !errors.Is(err, notify.ErrNotFound) {
		t.Fatalf("foreign audience mutation: %v", err)
	}
	if _, err = s.List(ctx, in.Recipient, notify.ListOptions{UnreadOnly: true, Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("changed filter cursor: %v", err)
	}
}

func TestErasureFencesConcurrentAndDelayedPublish(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	in := input("before-erasure")
	if _, err := s.Publish(ctx, in); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = s.EraseRecipientTx(ctx, tx, in.Recipient); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := s.Publish(ctx, input("racing")); result <- err }()
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-result; !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("race resurrected erased recipient: %v", err)
	}
	if _, err = s.Publish(ctx, in); !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("delayed replay: %v", err)
	}
	page, err := s.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("erased inbox: %+v %v", page, err)
	}
	op := input("operator")
	op.Recipient.Audience = notify.AudienceOperator
	if _, err = s.Publish(ctx, op); err != nil {
		t.Fatalf("user erasure crossed audience: %v", err)
	}
}

func TestOldTransactionSnapshotCannotResurrectErasedRecipient(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "first-publication", true: "existing-recipient"}[existing], func(t *testing.T) {
			s, pool, _ := database(t)
			ctx := t.Context()
			in := input("delayed")
			if existing {
				if _, err := s.Publish(ctx, input("before")); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM `+s.table).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if err = s.EraseRecipient(ctx, in.Recipient); err != nil {
				t.Fatal(err)
			}
			if _, err = s.PublishTx(ctx, tx, in); err == nil {
				t.Fatal("old snapshot published after account erasure")
			}
		})
	}
}

func TestClassificationMigrationKeepsOlderWorkflowProducersWorking(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	// Recreate the prior schema in this test's isolated namespace, with one
	// already-persisted workflow item, then perform the real additive upgrade.
	before, err := s.Publish(ctx, input("before-upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `ALTER TABLE `+s.table+` DROP COLUMN action_requested, DROP COLUMN source_subject, DROP COLUMN dismissed_at, DROP COLUMN visibility CASCADE, DROP COLUMN app_id CASCADE, DROP COLUMN producer_revision CASCADE, DROP COLUMN withdrawn CASCADE, DROP COLUMN producer_hash CASCADE; DELETE FROM `+pgx.Identifier{schema, "notify_migrations"}.Sanitize()+` WHERE version>=2`); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, pool, schema); err != nil {
		t.Fatal(err)
	}
	// A still-running older binary omits the new optional column entirely.
	_, err = pool.Exec(ctx, `INSERT INTO `+s.table+`(scope,id,audience,recipient,source,source_scope,source_id,kind,data,created_at,status) VALUES($1,'older-producer','user','alice','billing.example','merchant-1','old-writer','payment.failed','{}',now(),'open')`, s.scope)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, before.Recipient, notify.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("upgrade lost items: %+v", page)
	}
	for _, n := range page.Items {
		if !n.ActionRequested || n.Status != notify.StatusOpen || n.Origin.Subject != "" || n.DismissedAt != nil {
			t.Fatalf("workflow category lost: %+v", n)
		}
	}
}
