package postgres

import (
	"errors"
	"github.com/open-rails/authkit/notify"
	"testing"
)

func TestOriginScopesFilterBeforePagingAndMutations(t *testing.T) {
	base, pool, schema := database(t)
	ctx := t.Context()
	for _, id := range []string{"a", "b", "c", "d"} {
		n := input(id)
		n.Origin.Scope = id
		if _, err := base.Publish(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	view, err := New(pool, Config{Schema: schema, Scope: "tenant-a", Origins: []notify.OriginScope{{System: "billing.example", Scope: "a"}, {System: "billing.example", Scope: "c"}}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := view.List(ctx, input("a").Recipient, notify.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page %+v %v", page, err)
	}
	next, err := view.List(ctx, input("a").Recipient, notify.ListOptions{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.NextCursor != "" {
		t.Fatalf("second page %+v %v", next, err)
	}
	other, _ := New(pool, Config{Schema: schema, Scope: "tenant-a", Origins: []notify.OriginScope{{System: "billing.example", Scope: "b"}}})
	if _, err := other.List(ctx, input("a").Recipient, notify.ListOptions{Limit: 1, Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("cursor crossed origin view: %v", err)
	}
	all, _ := base.List(ctx, input("a").Recipient, notify.ListOptions{})
	for _, n := range all.Items {
		if n.Origin.Scope != "b" {
			continue
		}
		if _, err := view.Get(ctx, n.Recipient, n.ID); !errors.Is(err, notify.ErrNotFound) {
			t.Fatalf("get escaped: %v", err)
		}
		if _, err := view.SetRead(ctx, n.Recipient, n.ID, true); !errors.Is(err, notify.ErrNotFound) {
			t.Fatalf("read escaped: %v", err)
		}
		if _, err := view.SetDismissed(ctx, n.Recipient, n.ID, true); !errors.Is(err, notify.ErrNotFound) {
			t.Fatalf("dismiss escaped: %v", err)
		}
	}
	denied, _ := New(pool, Config{Schema: schema, Scope: "tenant-a", Origins: []notify.OriginScope{}})
	empty, err := denied.List(ctx, input("a").Recipient, notify.ListOptions{})
	if err != nil || len(empty.Items) != 0 {
		t.Fatalf("explicit empty origins %+v %v", empty, err)
	}
}
