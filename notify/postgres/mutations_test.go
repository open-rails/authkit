package postgres

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/notify"
)

func mutation(id string, revision int64, withdrawn bool) notify.Mutation {
	in := input(id)
	in.Visibility, in.AppID = notify.VisibilityApp, "app-a"
	return notify.Mutation{Input: in, Revision: revision, Withdrawn: withdrawn}
}

func singleItem(t *testing.T, s *Store, r notify.Recipient, dismissed bool) notify.Item {
	t.Helper()
	page, err := s.List(t.Context(), r, notify.ListOptions{Dismissed: dismissed})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("expected one receipt, got %+v: %v", page, err)
	}
	return page.Items[0]
}

func noItems(t *testing.T, s *Store, r notify.Recipient) {
	t.Helper()
	for _, dismissed := range []bool{false, true} {
		page, err := s.List(t.Context(), r, notify.ListOptions{Dismissed: dismissed})
		if err != nil || len(page.Items) != 0 {
			t.Fatalf("withdrawn receipt leaked (dismissed=%t): %+v %v", dismissed, page, err)
		}
	}
}

func TestProducerReplayWithdrawalAndReopenPreserveReceiptSemantics(t *testing.T) {
	s, _, _ := database(t)
	ctx := t.Context()
	in := mutation("payment-method:expired", 10, false)
	if err := s.Apply(ctx, []notify.Mutation{in}); err != nil {
		t.Fatal(err)
	}
	first := singleItem(t, s, in.Recipient, false)
	if first.ProducerRevision != 10 || first.Revision != 1 {
		t.Fatalf("source and receipt revisions conflated: %+v", first)
	}
	read, err := s.SetRead(ctx, in.Recipient, first.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := s.Transition(ctx, in.Recipient, first.ID, read.Revision, notify.StatusResolved)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := s.SetDismissed(ctx, in.Recipient, first.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	// JSON key order/whitespace is not a different producer message. The
	// exact large monetary value must survive canonicalization without floats.
	in.Data = []byte(`{ "future": { "field": true }, "amount": "9007199254740993" }`)
	if err := s.Apply(ctx, []notify.Mutation{in}); err != nil {
		t.Fatal(err)
	}
	got := singleItem(t, s, in.Recipient, true)
	if got.ID != first.ID || got.ProducerRevision != 10 || got.Revision != archived.Revision || got.ReadAt == nil || got.DismissedAt == nil || got.Status != resolved.Status {
		t.Fatalf("replay reset receipt/workflow state: %+v", got)
	}
	in.Revision, in.Data = 11, []byte(`{"amount":9007199254740993,"updated":true}`)
	if err := s.Apply(ctx, []notify.Mutation{in}); err != nil {
		t.Fatal(err)
	}
	got = singleItem(t, s, in.Recipient, true)
	if got.ReadAt == nil || got.DismissedAt == nil || got.Status != notify.StatusOpen || got.ProducerRevision != 11 {
		t.Fatalf("update reset read/archive state: %+v", got)
	}
	before := got.Revision
	stale := mutation(in.Origin.ID, 9, false)
	if err := s.Apply(ctx, []notify.Mutation{stale}); err != nil {
		t.Fatal(err)
	}
	if got = singleItem(t, s, in.Recipient, true); got.Revision != before || got.ProducerRevision != 11 {
		t.Fatalf("stale delivery replaced current producer state: %+v", got)
	}
	conflict := in
	conflict.Data = []byte(`{"different":true}`)
	if err := s.Apply(ctx, []notify.Mutation{conflict}); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("one producer revision accepted conflicting content: %v", err)
	}
	if got = singleItem(t, s, in.Recipient, true); got.Revision != before {
		t.Fatalf("stale/conflicting delivery changed receipt: %+v", got)
	}
	withdraw := mutation(in.Origin.ID, 12, true)
	if err := s.Apply(ctx, []notify.Mutation{withdraw}); err != nil {
		t.Fatal(err)
	}
	noItems(t, s, in.Recipient)
	checks := []struct {
		name string
		run  func() error
	}{
		{"get", func() error { _, err := s.Get(ctx, in.Recipient, first.ID); return err }},
		{"read", func() error { _, err := s.SetRead(ctx, in.Recipient, first.ID, false); return err }},
		{"unarchive", func() error { _, err := s.SetDismissed(ctx, in.Recipient, first.ID, false); return err }},
		{"transition", func() error {
			_, err := s.Transition(ctx, in.Recipient, first.ID, before, notify.StatusResolved)
			return err
		}},
	}
	for _, check := range checks {
		if err := check.run(); !errors.Is(err, notify.ErrNotFound) {
			t.Errorf("%s exposed withdrawn receipt: %v", check.name, err)
		}
	}
	if legacy, err := s.Publish(ctx, in.Input); err != nil || !legacy.Withdrawn {
		t.Fatalf("legacy publication reopened withdrawn receipt: %+v %v", legacy, err)
	}
	noItems(t, s, in.Recipient)
	in.Revision = 13
	if err := s.Apply(ctx, []notify.Mutation{in}); err != nil {
		t.Fatal(err)
	}
	got = singleItem(t, s, in.Recipient, false)
	if got.ID != first.ID || got.ProducerRevision != 13 || got.ReadAt != nil || got.DismissedAt != nil || got.Withdrawn {
		t.Fatalf("newer reopen not visible and unread: %+v", got)
	}
}

func TestWithdrawalBeforePublishAndImmutableVisibility(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	withdraw := mutation("comment.reply:B", 2, true)
	withdraw.Input = notify.Input{Recipient: withdraw.Recipient, Origin: withdraw.Origin, Visibility: withdraw.Visibility, AppID: withdraw.AppID}
	if err := s.Apply(ctx, []notify.Mutation{withdraw}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, []notify.Mutation{mutation(withdraw.Origin.ID, 1, false)}); err != nil {
		t.Fatal(err)
	}
	noItems(t, s, withdraw.Recipient)
	if err := s.Apply(ctx, []notify.Mutation{withdraw}); err != nil {
		t.Fatal(err)
	}
	noItems(t, s, withdraw.Recipient)
	var revision int64
	var hidden bool
	if err := pool.QueryRow(ctx, `SELECT producer_revision,withdrawn FROM `+s.table+` WHERE source_id=$1`, withdraw.Origin.ID).Scan(&revision, &hidden); err != nil || revision != 2 || !hidden {
		t.Fatalf("missing withdrawal marker: %d %t %v", revision, hidden, err)
	}
	wrong := mutation(withdraw.Origin.ID, 3, false)
	wrong.AppID = "app-b"
	if err := s.Apply(ctx, []notify.Mutation{wrong}); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("same key moved to another app: %v", err)
	}
	other, err := New(pool, Config{Schema: schema, Scope: "other-tenant"})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Apply(ctx, []notify.Mutation{mutation(withdraw.Origin.ID, 1, false)}); err != nil {
		t.Fatal(err)
	}
	singleItem(t, other, withdraw.Recipient, false)
	view, err := New(pool, Config{Schema: schema, Scope: s.scope, AppView: &notify.AppView{AppID: "app-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Apply(ctx, []notify.Mutation{withdraw}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("other app withdrew an app-a notification: %v", err)
	}
	if err := s.EraseRecipient(ctx, withdraw.Recipient); err != nil {
		t.Fatal(err)
	}
	for _, in := range []notify.Mutation{withdraw, mutation(withdraw.Origin.ID, 4, false)} {
		if err := s.Apply(ctx, []notify.Mutation{in}); !errors.Is(err, notify.ErrRecipientErased) {
			t.Fatalf("erased recipient accepted mutation: %v", err)
		}
	}
}

func TestMutationBatchAndCallerTransactionRollback(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	seed := mutation("seed", 1, false)
	if err := s.Apply(ctx, []notify.Mutation{seed}); err != nil {
		t.Fatal(err)
	}
	conflict := seed
	conflict.Data = []byte(`{"conflicting":true}`)
	batch := []notify.Mutation{mutation("first-in-batch", 1, false), conflict}
	if err := s.Apply(ctx, batch); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("conflicting batch accepted: %v", err)
	}
	if got := singleItem(t, s, seed.Recipient, false); got.Origin.ID != seed.Origin.ID {
		t.Fatalf("failed batch partially committed: %+v", got)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE `+pgx.Identifier{schema, "domain_change"}.Sanitize()+`(id integer PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO `+pgx.Identifier{schema, "domain_change"}.Sanitize()+` VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyTx(ctx, tx, batch); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("conflicting joined batch accepted: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{schema, "domain_change"}.Sanitize()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("batch savepoint aborted caller's other work: %d %v", n, err)
	}
	singleItem(t, s, seed.Recipient, false)
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyTx(ctx, tx, []notify.Mutation{mutation("rolled-back-marker", 2, true)}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, []notify.Mutation{mutation("rolled-back-marker", 1, false)}); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, seed.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("rolled-back withdrawal fenced later publish: %+v %v", page, err)
	}
}

func TestConcurrentProducerRevisionsConverge(t *testing.T) {
	s, _, _ := database(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for revision := int64(1); revision <= 20; revision++ {
		wg.Go(func() {
			in := mutation("shared-issue", revision, revision%2 == 1)
			in.Data = []byte(fmt.Sprintf(`{"revision":%d}`, revision))
			errs <- s.Apply(ctx, []notify.Mutation{in})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got := singleItem(t, s, input("shared-issue").Recipient, false)
	if got.ProducerRevision != 20 || string(got.Data) != `{"revision": 20}` {
		t.Fatalf("concurrent revisions did not converge: %+v", got)
	}
}

func TestProducerMutationsCannotCrossAnAppErasure(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	in := mutation("before-erasure", 1, false)
	if err := s.Apply(ctx, []notify.Mutation{in}); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+s.recipients).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := s.EraseAppRecipient(ctx, in.Recipient, "app-a", notify.OriginScope{}); err != nil {
		t.Fatal(err)
	}
	in.Revision = 2
	if err := s.ApplyTx(ctx, tx, []notify.Mutation{in}); err == nil {
		t.Fatal("old repeatable-read snapshot recreated erased app receipt")
	}
	if err := s.Apply(ctx, []notify.Mutation{in}); !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("fresh delayed mutation recreated erased app receipt: %v", err)
	}
	noItems(t, s, in.Recipient)
	otherApp := in
	otherApp.AppID, otherApp.Origin.ID = "app-b", "other-app"
	if err := s.Apply(ctx, []notify.Mutation{otherApp}); err != nil {
		t.Fatalf("one app erasure blocked another app: %v", err)
	}
	singleItem(t, s, in.Recipient, false)
}

func TestMergeKeepsLatestProducerRevisionAndWithdrawal(t *testing.T) {
	source, pool, schema := database(t)
	destination, err := New(pool, Config{Schema: schema, Scope: "new-account-scope"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := source.Apply(ctx, []notify.Mutation{mutation("issue", 2, true)}); err != nil {
		t.Fatal(err)
	}
	if err := destination.Apply(ctx, []notify.Mutation{mutation("issue", 1, false)}); err != nil {
		t.Fatal(err)
	}
	before := singleItem(t, destination, input("issue").Recipient, false)
	if err := destination.MergeFrom(ctx, []LegacyScope{{Schema: schema, Scope: source.scope}}); err != nil {
		t.Fatal(err)
	}
	noItems(t, destination, before.Recipient)
	if err := destination.Apply(ctx, []notify.Mutation{mutation("issue", 1, false)}); err != nil {
		t.Fatal(err)
	}
	noItems(t, destination, before.Recipient)
	if err := destination.Apply(ctx, []notify.Mutation{mutation("issue", 3, false)}); err != nil {
		t.Fatal(err)
	}
	if got := singleItem(t, destination, before.Recipient, false); got.ID != before.ID || got.ProducerRevision != 3 {
		t.Fatalf("merge replaced receipt identity: %+v", got)
	}
	// Re-running migration cannot let a lower source withdrawal replace the
	// newer destination reopen.
	if err := destination.MergeFrom(ctx, []LegacyScope{{Schema: schema, Scope: source.scope}}); err != nil {
		t.Fatal(err)
	}
	singleItem(t, destination, before.Recipient, false)
	conflicting := mutation("issue", 3, false)
	conflicting.Data = []byte(`{"conflicting":true}`)
	if err := source.Apply(ctx, []notify.Mutation{conflicting}); err != nil {
		t.Fatal(err)
	}
	if err := destination.MergeFrom(ctx, []LegacyScope{{Schema: schema, Scope: source.scope}}); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("migration accepted divergent source revision: %v", err)
	}
}
