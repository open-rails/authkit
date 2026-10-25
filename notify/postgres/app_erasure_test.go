package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/notify"
)

func TestAppErasurePreservesSharedInboxAndFencesReplay(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	base := input("unused")
	native := notify.OriginScope{System: "contentkit", Scope: "a"}
	makeInput := func(id string, v notify.Visibility, app, sourceScope string) notify.Input {
		in := base
		in.Origin = notify.Origin{System: "contentkit", Scope: sourceScope, ID: id}
		in.Visibility, in.AppID = v, app
		return in
	}
	appA, legacyA := makeInput("a", notify.VisibilityApp, "app-a", "a"), makeInput("legacy-a", "", "", "a")
	keep := []notify.Input{makeInput("b", notify.VisibilityApp, "app-b", "b"), makeInput("legacy-b", "", "", "b"), makeInput("tenant", notify.VisibilityTenant, "", "a"), input("billing")}
	for _, in := range append([]notify.Input{appA, legacyA}, keep...) {
		if _, err := s.Publish(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.EraseAppRecipient(ctx, base.Recipient, "app-a", native); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, base.Recipient, notify.ListOptions{})
	if err != nil || len(page.Items) != len(keep) {
		t.Fatalf("app erasure crossed inbox: %+v %v", page, err)
	}
	for _, in := range []notify.Input{appA, legacyA} {
		if _, err := s.Publish(ctx, in); !errors.Is(err, notify.ErrRecipientErased) {
			t.Fatalf("app replay returned %v", err)
		}
	}
	for _, in := range keep {
		if _, err := s.Publish(ctx, in); err != nil {
			t.Fatalf("shared/sibling event fenced: %v", err)
		}
	}
	// This bypasses the new Go guard, like an older publisher. The database
	// trigger must still reject the deleted app's event.
	_, err = pool.Exec(ctx, `INSERT INTO `+s.table+`(scope,id,audience,recipient,source,source_scope,source_id,kind,data,created_at) VALUES($1,'raw','user','alice','contentkit','a','raw','test','{}',now())`, s.scope)
	if err == nil {
		t.Fatal("older publisher recreated erased app notice")
	}
	var globallyErased bool
	if err := pool.QueryRow(ctx, `SELECT erased_at IS NOT NULL FROM `+s.recipients+` WHERE scope=$1 AND audience='user' AND recipient='alice'`, s.scope).Scan(&globallyErased); err != nil || globallyErased {
		t.Fatalf("app erasure became account erasure: %v %v", globallyErased, err)
	}
}

func TestAppErasureRejectsOldSnapshot(t *testing.T) {
	s, pool, _ := database(t)
	ctx := t.Context()
	in := input("old-snapshot")
	in.Visibility, in.AppID = notify.VisibilityApp, "app-a"
	if _, err := s.Publish(ctx, input("seed")); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+s.table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := s.EraseAppRecipient(ctx, in.Recipient, "app-a", notify.OriginScope{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PublishTx(ctx, tx, in); err == nil {
		t.Fatal("old snapshot bypassed app erasure")
	}
}

func TestAppErasureSurvivesInboxMerge(t *testing.T) {
	source, _, sourceSchema := database(t)
	target, _, _ := database(t)
	ctx := t.Context()
	in := input("app-replay")
	in.Visibility, in.AppID = notify.VisibilityApp, "app-a"
	if _, err := target.Publish(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := source.EraseAppRecipient(ctx, in.Recipient, "app-a", notify.OriginScope{}); err != nil {
		t.Fatal(err)
	}
	if err := target.MergeFrom(ctx, []LegacyScope{{Schema: sourceSchema, Scope: source.scope}}); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Publish(ctx, in); !errors.Is(err, notify.ErrRecipientErased) {
		t.Fatalf("merged fence lost: %v", err)
	}
	in.Origin.ID = "tenant-survives"
	in.Visibility, in.AppID = notify.VisibilityTenant, ""
	if _, err := target.Publish(ctx, in); err != nil {
		t.Fatal(err)
	}
}
