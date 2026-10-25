package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/notify"
)

func TestAppViewSeparatesVisibilityFromOriginAndPreservesSharedReceipt(t *testing.T) {
	all, pool, schema := database(t)
	ctx := t.Context()
	user := input("id").Recipient
	var sequence int
	publish := func(id string, v notify.Visibility, app, origin string) notify.Item {
		t.Helper()
		n := input(id)
		sequence++
		n.CreatedAt = n.CreatedAt.Add(time.Duration(sequence) * time.Second)
		n.Visibility = v
		n.AppID = app
		n.Origin.Scope = origin
		got, err := all.Publish(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	shared := publish("shared", notify.VisibilityTenant, "", "arbitrary-producer")
	own := publish("own", notify.VisibilityApp, "a", "arbitrary-producer")
	sibling := publish("sibling", notify.VisibilityApp, "b", "known-legacy")
	legacy := publish("legacy", "", "", "known-legacy")
	publish("unknown", "", "", "unknown-legacy")
	newView := func(app string, legacy []notify.OriginScope) *Store {
		t.Helper()
		s, err := New(pool, Config{Schema: schema, Scope: "tenant-a", AppView: &notify.AppView{AppID: app, LegacyOrigins: legacy}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := newView("a", []notify.OriginScope{{System: "billing.example", Scope: "known-legacy"}})
	b := newView("b", nil)
	page, err := a.List(ctx, user, notify.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != legacy.ID || page.NextCursor == "" {
		t.Fatalf("first page %+v %v", page, err)
	}
	if _, err := b.List(ctx, user, notify.ListOptions{Limit: 1, Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("cursor crossed app: %v", err)
	}
	page, err = a.List(ctx, user, notify.ListOptions{Limit: 100})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("a visibility %+v %v", page, err)
	}
	for _, n := range page.Items {
		if n.ID != own.ID && n.ID != shared.ID && n.ID != legacy.ID {
			t.Fatalf("origin allowed a sibling app %+v", n)
		}
	}
	for _, get := range []func() (notify.Item, error){
		func() (notify.Item, error) { return a.Get(ctx, user, sibling.ID) },
		func() (notify.Item, error) { return a.SetRead(ctx, user, sibling.ID, true) },
		func() (notify.Item, error) { return a.SetDismissed(ctx, user, sibling.ID, true) },
		func() (notify.Item, error) {
			return a.Transition(ctx, user, sibling.ID, sibling.Revision, notify.StatusResolved)
		},
	} {
		if _, err := get(); !errors.Is(err, notify.ErrNotFound) {
			t.Fatalf("sibling mutation escaped view: %v", err)
		}
	}
	attempted := input("unknown")
	attempted.Origin.Scope = "unknown-legacy"
	attempted.Visibility = notify.VisibilityApp
	attempted.AppID = "a"
	if _, err := a.Publish(ctx, attempted); !errors.Is(err, notify.ErrNotFound) {
		t.Fatalf("publish leaked hidden legacy replay: %v", err)
	}
	if _, err := a.SetRead(ctx, user, shared.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetDismissed(ctx, user, shared.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(ctx, user, shared.ID)
	if err != nil || got.ReadAt == nil || got.DismissedAt == nil {
		t.Fatalf("shared receipt %+v %v", got, err)
	}
	if err := b.EraseRecipient(ctx, user); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Publish(ctx, own.Input); !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("tenant erasure did not fence apps: %v", err)
	}
}

func TestVisibilityReplayAndExplicitLegacyClassification(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	in := input("legacy")
	legacy, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRead(ctx, in.Recipient, legacy.ID, true); err != nil {
		t.Fatal(err)
	}
	in.Visibility = notify.VisibilityApp
	in.AppID = "a"
	view, err := New(pool, Config{Schema: schema, Scope: "tenant-a", AppView: &notify.AppView{AppID: "a", LegacyOrigins: []notify.OriginScope{{System: in.Origin.System, Scope: in.Origin.Scope}}}})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := view.Publish(ctx, in)
	if err != nil || replay.Visibility != "" || replay.ID != legacy.ID || replay.ReadAt == nil {
		t.Fatalf("replay relabeled legacy %+v %v", replay, err)
	}
	changed, err := s.ClassifyLegacyOrigins(ctx, []LegacyVisibility{{Origin: notify.OriginScope{System: in.Origin.System, Scope: in.Origin.Scope}, Visibility: notify.VisibilityApp, AppID: "a"}})
	if err != nil || changed != 1 {
		t.Fatalf("migration changed %d: %v", changed, err)
	}
	replay, err = view.Publish(ctx, in)
	if err != nil || replay.Visibility != notify.VisibilityApp || replay.AppID != "a" || replay.ID != legacy.ID || replay.ReadAt == nil {
		t.Fatalf("classified replay %+v %v", replay, err)
	}
	in.AppID = "b"
	if _, err := s.Publish(ctx, in); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("explicit replay changed apps: %v", err)
	}
	in.Visibility = notify.VisibilityTenant
	in.AppID = ""
	if _, err := s.Publish(ctx, in); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("explicit replay broadened visibility: %v", err)
	}
}

func TestMergeFromUnclassifiedOlderSchema(t *testing.T) {
	source, _, schema := database(t)
	destination, _, _ := database(t)
	ctx := t.Context()
	in := input("old-schema")
	old, err := source.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.SetRead(ctx, in.Recipient, old.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := source.pool.Exec(ctx, `ALTER TABLE `+source.table+` DROP COLUMN visibility CASCADE, DROP COLUMN app_id CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := destination.MergeFrom(ctx, []LegacyScope{{Schema: schema, Scope: "tenant-a"}}); err != nil {
		t.Fatal(err)
	}
	page, err := destination.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != 1 || page.Items[0].Visibility != "" || page.Items[0].ReadAt == nil || page.Items[0].ID != old.ID {
		t.Fatalf("older receipt lost %+v %v", page, err)
	}
}

func TestClassificationRefusesVersionedUnclassifiedOriginsAtomically(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	legacy := input("legacy-classification")
	legacy.Origin.Scope = "legacy-origin"
	old, err := s.Publish(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	versioned := notify.Mutation{Input: input("versioned-unclassified"), Revision: 1}
	if err := s.Apply(ctx, []notify.Mutation{versioned}); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := pool.QueryRow(ctx, `SELECT encode(producer_hash,'hex') FROM `+s.table+` WHERE scope=$1 AND source_id=$2`, s.scope, versioned.Origin.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	mappings := []LegacyVisibility{
		{Origin: notify.OriginScope{System: legacy.Origin.System, Scope: legacy.Origin.Scope}, Visibility: notify.VisibilityApp, AppID: "app-a"},
		{Origin: notify.OriginScope{System: versioned.Origin.System, Scope: versioned.Origin.Scope}, Visibility: notify.VisibilityApp, AppID: "app-a"},
	}
	if n, err := s.ClassifyLegacyOrigins(ctx, mappings); !errors.Is(err, notify.ErrConflict) || n != 0 {
		t.Fatalf("classification rewrote a producer-owned mutation: count=%d err=%v", n, err)
	}
	var visibility, appID, after string
	var revision, producerRevision int64
	if err := pool.QueryRow(ctx, `SELECT visibility,app_id,revision,producer_revision,encode(producer_hash,'hex') FROM `+s.table+` WHERE scope=$1 AND source_id=$2`, s.scope, versioned.Origin.ID).Scan(&visibility, &appID, &revision, &producerRevision, &after); err != nil {
		t.Fatal(err)
	}
	if visibility != "" || appID != "" || revision != 1 || producerRevision != 1 || before != after {
		t.Fatalf("refused classification changed producer state: visibility=%q app=%q revision=%d producer=%d hash=%s, want %s", visibility, appID, revision, producerRevision, after, before)
	}
	retained, err := s.Get(ctx, legacy.Recipient, old.ID)
	if err != nil || retained.Visibility != "" || retained.AppID != "" || retained.Revision != old.Revision {
		t.Fatalf("mixed classification partly changed legacy receipt: %+v %v", retained, err)
	}
	if err := s.Apply(ctx, []notify.Mutation{versioned}); err != nil {
		t.Fatalf("refused classification broke exact producer replay: %v", err)
	}
	if n, err := s.ClassifyLegacyOrigins(ctx, mappings[:1]); err != nil || n != 1 {
		t.Fatalf("unversioned legacy classification stopped working: %d %v", n, err)
	}
	retained, err = s.Get(ctx, legacy.Recipient, old.ID)
	if err != nil || retained.Visibility != notify.VisibilityApp || retained.AppID != "app-a" || retained.ProducerRevision != 0 {
		t.Fatalf("legacy classification corrupted source ordering: %+v %v", retained, err)
	}
}
