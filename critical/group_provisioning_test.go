package critical_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

func TestCriticalConfiguredGroups(t *testing.T) {
	f := newFixture(t)
	poolConfig := f.pool.Config().Copy()
	poolConfig.MaxConns, poolConfig.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	noError(t, err)
	t.Cleanup(pool.Close)
	// No issuer, HTTP, sender, signing key or running worker is supplied.
	cfg := authkit.Config{Database: f.cfg.Database, Roles: f.roles, DefaultTenantID: f.tenant}
	ensure := func(ctx context.Context, groups ...iam.NewGroup) ([]iam.Group, error) {
		return authkit.EnsureGroups(ctx, pool, cfg, groups)
	}
	newGroup := func() iam.NewGroup {
		return iam.NewGroup{ID: iam.NewTenantID().String(), Persona: f.shop.Persona}
	}
	createdEvents := func(id string) int {
		page, err := f.auth.ListEvents(t.Context(), iam.EventQuery{Limit: 500})
		noError(t, err)
		n := 0
		for _, event := range page.Events {
			if event.Kind == iam.EventGroupCreated && event.GroupID == id {
				n++
			}
		}
		return n
	}

	t.Run("AK-J36-C01_keyless_one_connection_preserves_members_and_events", func(t *testing.T) {
		before := pool.Config().ConnConfig.RuntimeParams["search_path"]
		cfg.Keys.Path = filepath.Join(t.TempDir(), "must-not-be-created")
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		input := newGroup()
		groups, err := ensure(ctx, input)
		noError(t, err)
		if len(groups) != 1 || groups[0].ID != input.ID || groups[0].TenantID != f.tenant || groups[0].Persona != f.shop.Persona {
			t.Fatalf("wrong configured group: %+v", groups)
		}
		members, err := f.auth.ListGroupMembers(t.Context(), iam.GroupByID(input.ID), iam.MemberQuery{})
		noError(t, err)
		if len(members.Items) != 0 {
			t.Fatal("provisioning assigned a user")
		}
		u := f.user(t)
		f.grant(t, groups[0], u, f.writer)
		again, err := ensure(ctx, input)
		noError(t, err)
		if !reflect.DeepEqual(groups, again) || createdEvents(input.ID) != 1 {
			t.Fatal("replay changed group identity or emitted another create event")
		}
		roles, err := f.auth.GroupRoles(t.Context(), iam.GroupByID(input.ID), []iam.Subject{iam.UserSubject(u.ID)})
		noError(t, err)
		if roles[iam.UserSubject(u.ID)] != f.writer {
			t.Fatal("replay changed the editor's grant")
		}
		if _, err := os.Stat(cfg.Keys.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("provisioning touched signing key storage: %v", err)
		}
		if pool.Config().ConnConfig.RuntimeParams["search_path"] != before {
			t.Fatal("provisioning mutated the caller's pool")
		}
	})

	t.Run("AK-J36-C02_bad_configuration_is_rejected_before_writes", func(t *testing.T) {
		unknown := authkit.NewRoles().Persona("unconfigured").Persona
		owner := iam.UserSubject(iam.NewTenantID().String())
		bad := []iam.NewGroup{
			{Persona: f.shop.Persona},
			{ID: "not-an-id", Persona: f.shop.Persona},
			{ID: iam.NewTenantID().String(), Persona: iam.RootPersona()},
			{ID: iam.NewTenantID().String(), Persona: unknown},
			{ID: iam.NewTenantID().String(), Persona: f.shop.Persona, Owner: &owner},
			{ID: iam.NewTenantID().String(), Persona: f.shop.Persona, TenantID: iam.NewTenantID()},
		}
		for _, invalid := range bad {
			first := newGroup()
			if result, err := ensure(t.Context(), first, invalid); err == nil || len(result) != 0 {
				t.Fatalf("invalid configuration was accepted: %+v, %v", result, err)
			}
			if _, err := f.auth.Group(t.Context(), iam.GroupByID(first.ID)); !errors.Is(err, iam.ErrGroupNotFound) {
				t.Fatalf("invalid batch wrote its valid prefix: %v", err)
			}
		}
		duplicate := newGroup()
		conflict := duplicate
		conflict.Persona = f.team.Persona
		if _, err := ensure(t.Context(), duplicate, conflict); !errors.Is(err, iam.ErrGroupConflict) {
			t.Fatalf("conflicting duplicate ID was accepted: %v", err)
		}
		missingTenant := cfg
		missingTenant.DefaultTenantID = iam.TenantID{}
		if _, err := authkit.EnsureGroups(t.Context(), pool, missingTenant, []iam.NewGroup{newGroup()}); !errors.Is(err, iam.ErrTenantRequired) {
			t.Fatalf("missing tenant accepted: %v", err)
		}
		noError(t, pool.Ping(t.Context()))
	})

	t.Run("AK-J36-C03_existing_foreign_and_deleted_groups_are_not_replaced", func(t *testing.T) {
		input := newGroup()
		groups, err := ensure(t.Context(), input)
		noError(t, err)
		otherTenant := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: otherTenant, Slug: "provisioning-other"}))
		wrong := input
		wrong.TenantID = otherTenant
		if _, err := ensure(t.Context(), wrong); !errors.Is(err, iam.ErrGroupConflict) {
			t.Fatalf("cross-tenant identity was accepted: %v", err)
		}
		wrong = input
		wrong.Persona = f.team.Persona
		if _, err := ensure(t.Context(), wrong); !errors.Is(err, iam.ErrGroupConflict) {
			t.Fatalf("cross-persona identity was accepted: %v", err)
		}
		noError(t, f.auth.DeleteGroup(t.Context(), iam.GroupByID(input.ID)))
		before, err := f.auth.Group(t.Context(), iam.GroupByID(input.ID))
		noError(t, err)
		if before.DeletedAt == nil {
			t.Fatal("fixture group was not deleted")
		}
		if _, err := ensure(t.Context(), input); !errors.Is(err, iam.ErrGroupConflict) {
			t.Fatalf("deleted group was revived: %v", err)
		}
		after, err := f.auth.Group(t.Context(), iam.GroupByID(input.ID))
		noError(t, err)
		if !reflect.DeepEqual(before, after) || after.CreatedAt != groups[0].CreatedAt || createdEvents(input.ID) != 1 {
			t.Fatal("refused provisioning replaced the deleted group")
		}
		noError(t, pool.Ping(t.Context()))
	})

	t.Run("AK-J36-C04_concurrent_migrations_and_retry_converge", func(t *testing.T) {
		input := newGroup()
		const clients = 4
		results := make(chan error, clients)
		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		for range clients {
			wg.Go(func() { _, err := ensure(ctx, input); results <- err })
		}
		wg.Wait()
		close(results)
		for err := range results {
			noError(t, err)
		}
		groups, err := ensure(ctx, input)
		noError(t, err)
		if len(groups) != 1 || groups[0].ID != input.ID || createdEvents(input.ID) != 1 {
			t.Fatal("concurrent provisioning duplicated a group or event")
		}
		cancelled, stop := context.WithCancel(t.Context())
		stop()
		next := newGroup()
		if _, err := ensure(cancelled, next); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled migration did not fail: %v", err)
		}
		_, err = ensure(t.Context(), next)
		noError(t, err)
		if createdEvents(next.ID) != 1 {
			t.Fatal("retry did not create one group event")
		}
	})
}
