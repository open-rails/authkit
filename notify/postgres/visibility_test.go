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

func TestExplicitVisibilityIsImmutableOnReplay(t *testing.T) {
	s, _, _ := database(t)
	ctx := t.Context()
	in := input("classified")
	in.Visibility, in.AppID = notify.VisibilityApp, "a"
	first, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.Publish(ctx, in)
	if err != nil || replay.ID != first.ID || replay.Visibility != notify.VisibilityApp || replay.AppID != "a" {
		t.Fatalf("replay %+v %v", replay, err)
	}
	in.AppID = "b"
	if _, err := s.Publish(ctx, in); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("explicit replay changed apps: %v", err)
	}
	in.Visibility, in.AppID = notify.VisibilityTenant, ""
	if _, err := s.Publish(ctx, in); !errors.Is(err, notify.ErrConflict) {
		t.Fatalf("explicit replay broadened visibility: %v", err)
	}
}
