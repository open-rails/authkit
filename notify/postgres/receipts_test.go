package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/open-rails/authkit/notify"
)

func TestAuthorizedRecipientsAreFilteredBeforePagination(t *testing.T) {
	s, pool, schema := database(t)
	ctx := t.Context()
	alice := input("first").Recipient
	bob := notify.Recipient{Audience: notify.AudienceUser, ID: "bob"}
	unlinked := notify.Recipient{Audience: notify.AudienceUser, ID: "unlinked"}
	var items []notify.Item
	for i, r := range []notify.Recipient{alice, bob, unlinked, unlinked, unlinked} {
		in := input(time.Duration(i).String())
		in.Recipient = r
		in.CreatedAt = in.CreatedAt.Add(time.Duration(i) * time.Minute)
		n, err := s.Publish(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, n)
	}
	allowed := []notify.Recipient{alice, bob}
	page, err := s.ListRecipients(ctx, allowed, notify.ListOptions{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != items[1].ID || page.NextCursor == "" {
		t.Fatalf("authorized first page: %+v, %v", page, err)
	}
	next, err := s.ListRecipients(ctx, []notify.Recipient{bob, alice, bob}, notify.ListOptions{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID != items[0].ID || next.NextCursor != "" {
		t.Fatalf("normalized authorization page: %+v, %v", next, err)
	}
	if _, err = s.ListRecipients(ctx, []notify.Recipient{alice}, notify.ListOptions{Cursor: page.NextCursor}); !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("changed authorization accepted old cursor: %v", err)
	}
	other, err := New(pool, Config{Schema: schema, Scope: "other"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		store      *Store
		recipients []notify.Recipient
	}{
		{"unlinked", s, []notify.Recipient{alice}},
		{"empty", s, nil},
		{"audience", s, []notify.Recipient{{Audience: notify.AudienceOperator, ID: bob.ID}}},
		{"scope", other, allowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.store.GetRecipients(ctx, tc.recipients, items[1].ID); !errors.Is(err, notify.ErrNotFound) {
				t.Fatalf("get: %v", err)
			}
			if _, err := tc.store.SetReadRecipients(ctx, tc.recipients, items[1].ID, true); !errors.Is(err, notify.ErrNotFound) {
				t.Fatalf("read: %v", err)
			}
			if _, err := tc.store.SetDismissedRecipients(ctx, tc.recipients, items[1].ID, true); !errors.Is(err, notify.ErrNotFound) {
				t.Fatalf("dismiss: %v", err)
			}
		})
	}
	empty, err := s.ListRecipients(ctx, nil, notify.ListOptions{})
	if err != nil || len(empty.Items) != 0 {
		t.Fatalf("empty authority: %+v %v", empty, err)
	}
}

func TestArchiveReadAndWorkflowHaveIndependentState(t *testing.T) {
	s, _, _ := database(t)
	ctx := t.Context()
	in := input("receipt")
	in.Origin.Subject = "source-customer"
	n, err := s.Publish(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := s.SetDismissed(ctx, in.Recipient, n.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if archived.DismissedAt == nil || archived.ReadAt != nil || archived.ResolvedAt != nil || archived.Status != notify.StatusOpen || archived.Revision != n.Revision+1 {
		t.Fatalf("archive changed workflow/read: %+v", archived)
	}
	retry, err := s.SetDismissed(ctx, in.Recipient, n.ID, true)
	if err != nil || retry.Revision != archived.Revision || !retry.DismissedAt.Equal(*archived.DismissedAt) {
		t.Fatalf("archive retry: %+v %v", retry, err)
	}
	active, err := s.List(ctx, in.Recipient, notify.ListOptions{})
	if err != nil || len(active.Items) != 0 {
		t.Fatalf("archive stayed active: %+v %v", active, err)
	}
	page, err := s.List(ctx, in.Recipient, notify.ListOptions{Dismissed: true, UnreadOnly: true})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("archive listing: %+v %v", page, err)
	}
	read, err := s.SetRead(ctx, in.Recipient, n.ID, true)
	if err != nil || read.ReadAt == nil || read.DismissedAt == nil || read.Status != notify.StatusOpen || read.Revision != archived.Revision+1 {
		t.Fatalf("read: %+v %v", read, err)
	}
	retry, err = s.SetRead(ctx, in.Recipient, n.ID, true)
	if err != nil || retry.Revision != read.Revision || !retry.ReadAt.Equal(*read.ReadAt) {
		t.Fatalf("read retry: %+v %v", retry, err)
	}
	in.Origin.Subject = "changed-source-customer"
	in.Data = []byte(`{"changed":true}`)
	replay, err := s.Publish(ctx, in)
	if err != nil || replay.ID != n.ID || replay.Revision != read.Revision || replay.ReadAt == nil || replay.DismissedAt == nil || replay.Origin.Subject != "source-customer" {
		t.Fatalf("replay changed receipt: %+v %v", replay, err)
	}
	resolved, err := s.Transition(ctx, in.Recipient, n.ID, read.Revision, notify.StatusResolved)
	if err != nil || resolved.DismissedAt == nil || resolved.ReadAt == nil {
		t.Fatalf("resolution: %+v %v", resolved, err)
	}
	restored, err := s.SetDismissed(ctx, in.Recipient, n.ID, false)
	if err != nil || restored.DismissedAt != nil || restored.Status != notify.StatusResolved || restored.ReadAt == nil || restored.Revision != resolved.Revision+1 {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	got, err := s.Get(ctx, in.Recipient, n.ID)
	if err != nil || got.Revision != restored.Revision {
		t.Fatalf("canonical get: %+v %v", got, err)
	}
}
