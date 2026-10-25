package postgres

import (
	"errors"
	"testing"

	"github.com/open-rails/authkit/notify"
)

func TestMergeFromPreservesReceiptsAndSourceStores(t *testing.T) {
	first, pool, schema := database(t)
	second, err := New(pool, Config{Schema: schema, Scope: "second"})
	if err != nil {
		t.Fatal(err)
	}
	dest, err := New(pool, Config{Schema: schema, Scope: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, in := t.Context(), input("shared-billing-event")
	a, err := first.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.SetRead(ctx, in.Recipient, a.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := second.SetDismissed(ctx, in.Recipient, b.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Transition(ctx, in.Recipient, b.ID, b.Revision+1, notify.StatusResolved); err != nil {
		t.Fatal(err)
	}
	sources := []LegacyScope{{schema, "second"}, {schema, "tenant-a"}}
	if err := dest.MergeFrom(ctx, sources); err != nil {
		t.Fatal(err)
	}
	page, err := dest.List(ctx, in.Recipient, notify.ListOptions{Dismissed: true})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("merged archive: %+v %v", page, err)
	}
	merged := page.Items[0]
	if merged.ReadAt == nil || merged.DismissedAt == nil || merged.Status != notify.StatusResolved || merged.ResolvedAt == nil || merged.Origin != in.Origin {
		t.Fatalf("lost receipt or origin state: %+v", merged)
	}
	if err := dest.MergeFrom(ctx, sources); err != nil {
		t.Fatal(err)
	}
	again, err := dest.Get(ctx, in.Recipient, merged.ID)
	if err != nil || again.Revision != merged.Revision || again.ID != merged.ID {
		t.Fatalf("repeat merge changed receipt: %+v %v", again, err)
	}
	if _, err := first.Get(ctx, in.Recipient, a.ID); err != nil {
		t.Fatalf("first source removed: %v", err)
	}
	if _, err := second.Get(ctx, in.Recipient, b.ID); err != nil {
		t.Fatalf("second source removed: %v", err)
	}
}

func TestMergeFromErasureWinsAcrossSchemas(t *testing.T) {
	source, _, schema := database(t)
	dest, _, _ := database(t)
	ctx, in := t.Context(), input("erased-account")
	if _, err := dest.Publish(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := source.EraseRecipient(ctx, in.Recipient); err != nil {
		t.Fatal(err)
	}
	if err := dest.MergeFrom(ctx, []LegacyScope{{schema, "tenant-a"}}); err != nil {
		t.Fatal(err)
	}
	page, err := dest.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("erased recipient survived consolidation: %+v %v", page, err)
	}
	if _, err := dest.Publish(ctx, in); !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("merged erasure did not fence delayed publication: %v", err)
	}
}
