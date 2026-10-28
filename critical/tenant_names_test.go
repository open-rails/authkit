package critical_test

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// #471: a tenant's slug is its renamable public name beside its stable UUID,
// with the OpenRails merchant-name rules. AuthKit tenants are permanent, so a
// name is released only by a rename's former name expiring.
func TestCriticalTenantNames(t *testing.T) {
	var operator, auditor iam.Role
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
		operator = c.Roles.Root.Role("tenantoperator", c.Roles.Root.Tenants.Read, c.Roles.Root.Tenants.Manage)
		auditor = c.Roles.Root.Role("tenantauditor", c.Roles.Root.Tenants.Read)
	}))
	ctx := t.Context()
	create := func(t *testing.T, slug string) iam.TenantID {
		t.Helper()
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: id, Slug: slug}))
		return id
	}
	resolves := func(t *testing.T, slug string, id iam.TenantID, current string) {
		t.Helper()
		got, err := f.auth.ResolveTenant(ctx, slug)
		noError(t, err)
		if got.ID != id || got.Slug != current {
			t.Fatalf("%q resolved to %s %q, want %s %q", slug, got.ID, got.Slug, id, current)
		}
	}
	unresolved := func(t *testing.T, slug string) {
		t.Helper()
		if got, err := f.auth.ResolveTenant(ctx, slug); !errors.Is(err, iam.ErrTenantNotFound) {
			t.Fatalf("%q resolved to %+v, %v; want not found", slug, got, err)
		}
	}
	isErr := func(t *testing.T, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	}
	aliases := pgx.Identifier{f.schema, "tenant_slug_aliases"}.Sanitize()

	t.Run("AK-J37-C01_create_requires_one_valid_unique_name", func(t *testing.T) {
		// Migration 0026 named the tenant migration 0018 adopted for this
		// deployment's default directory.
		adopted, err := f.auth.Tenant(ctx, f.tenant)
		noError(t, err)
		if want := "tenant-" + strings.ReplaceAll(f.tenant.String(), "-", ""); adopted.Slug != want || adopted.SlugChangedAt != nil {
			t.Fatalf("adopted tenant named %q (changed %v), want placeholder %q", adopted.Slug, adopted.SlugChangedAt, want)
		}
		id := iam.NewTenantID()
		noError(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: id, Slug: "  Acme-Shop "}))
		resolves(t, "ACME-shop", id, "acme-shop")
		noError(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: id, Slug: "acme-shop"}))
		isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: id, Slug: "acme-store"}), iam.ErrTenantConflict)
		resolves(t, "acme-shop", id, "acme-shop")
		unresolved(t, "acme-store")
		other := iam.NewTenantID()
		isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: other, Slug: "acme-shop"}), iam.ErrTenantNameTaken)
		if _, err := f.auth.ForTenant(ctx, other); !errors.Is(err, iam.ErrTenantNotFound) {
			t.Fatalf("a refused create left a tenant behind: %v", err)
		}
		isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{Slug: "no-id"}), iam.ErrTenantRequired)
		for _, bad := range []string{"", " ", "-acme", "acme-", "ac_me", "ac.me", "a b", "acmé", strings.Repeat("a", 64)} {
			isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: iam.NewTenantID(), Slug: bad}), iam.ErrInvalidTenantSlug)
			if _, err := f.auth.RenameTenant(ctx, id, bad); !errors.Is(err, iam.ErrInvalidTenantSlug) {
				t.Fatalf("rename to %q: %v", bad, err)
			}
		}
		// Reserved names are a hosted product's policy, not a format rule.
		for _, good := range []string{"a", "0", "admin", "a-b", strings.Repeat("z", 63)} {
			create(t, good)
		}
	})

	t.Run("AK-J37-C02_rename_keeps_identity_and_forwards_former_name", func(t *testing.T) {
		user := f.user(t)
		before := f.signIn(t, user)
		renamed, err := f.auth.RenameTenant(ctx, f.tenant, "Renamed-Default")
		noError(t, err)
		if renamed.ID != f.tenant || renamed.Slug != "renamed-default" || renamed.SlugChangedAt == nil {
			t.Fatalf("rename returned %+v", renamed)
		}
		placeholder := "tenant-" + strings.ReplaceAll(f.tenant.String(), "-", "")
		resolves(t, placeholder, f.tenant, "renamed-default")
		// The ID is the identity: sessions, tokens and accounts carry on.
		f.call(t, "GET", "/me", before.AccessToken, nil).want(t, http.StatusOK, "")
		after := f.signIn(t, user)
		credentials := []string{before.AccessToken, after.AccessToken}
		if after.RefreshToken != nil {
			credentials = append(credentials, *after.RefreshToken)
		}
		for _, token := range credentials {
			if strings.Contains(token, "renamed-default") || strings.Contains(token, placeholder) {
				t.Fatal("a tenant name reached a credential")
			}
		}
		if _, claims := jwtParts(t, after.AccessToken); claims["tenant_id"] != f.tenant.String() {
			t.Fatalf("token tenant claim = %v, want the UUID", claims["tenant_id"])
		}
		found, err := f.auth.User(ctx, iam.UserByID(user.ID))
		noError(t, err)
		if found.TenantID != f.tenant {
			t.Fatal("rename moved an account")
		}
		same, err := f.auth.RenameTenant(ctx, f.tenant, "renamed-default")
		noError(t, err)
		if !same.SlugChangedAt.Equal(*renamed.SlugChangedAt) {
			t.Fatal("renaming to the current name changed it")
		}

		north := create(t, "north-star")
		_, err = f.auth.RenameTenant(ctx, north, "pole-star")
		noError(t, err)
		resolves(t, "north-star", north, "pole-star")
		isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: iam.NewTenantID(), Slug: "north-star"}), iam.ErrTenantNameTaken)
		beta := create(t, "beta-star")
		_, err = f.auth.RenameTenant(ctx, beta, "north-star")
		isErr(t, err, iam.ErrTenantNameTaken)
		_, err = f.auth.RenameTenant(ctx, beta, "pole-star")
		isErr(t, err, iam.ErrTenantNameTaken)
		_, err = f.auth.RenameTenant(ctx, north, "beta-star")
		isErr(t, err, iam.ErrTenantNameTaken)
		resolves(t, "beta-star", beta, "beta-star")
		_, err = f.auth.RenameTenant(ctx, iam.NewTenantID(), "nobody-here")
		isErr(t, err, iam.ErrTenantNotFound)
	})

	t.Run("AK-J37-C03_tenant_takes_back_its_own_former_name", func(t *testing.T) {
		id := create(t, "first-name")
		_, err := f.auth.RenameTenant(ctx, id, "second-name")
		noError(t, err)
		back, err := f.auth.RenameTenant(ctx, id, "first-name")
		noError(t, err)
		if back.Slug != "first-name" {
			t.Fatalf("take-back returned %+v", back)
		}
		resolves(t, "first-name", id, "first-name")
		resolves(t, "second-name", id, "first-name")
		isErr(t, f.auth.CreateTenant(ctx, iam.Tenant{ID: iam.NewTenantID(), Slug: "second-name"}), iam.ErrTenantNameTaken)
		var held int
		noError(t, f.pool.QueryRow(ctx, "SELECT count(*) FROM "+aliases+" WHERE tenant_id=$1", id.String()).Scan(&held))
		if held != 1 {
			t.Fatalf("tenant holds %d former names, want only second-name", held)
		}
	})

	t.Run("AK-J37-C04_expired_former_name_is_free_to_claim", func(t *testing.T) {
		old := create(t, "old-brand")
		_, err := f.auth.RenameTenant(ctx, old, "new-brand")
		noError(t, err)
		var expires time.Time
		noError(t, f.pool.QueryRow(ctx, "SELECT expires_at FROM "+aliases+" WHERE slug='old-brand'").Scan(&expires))
		if until := time.Until(expires); until < 89*24*time.Hour || until > 91*24*time.Hour {
			t.Fatalf("default former name lasts %v, want 90 days", until)
		}
		resolves(t, "old-brand", old, "new-brand")
		// Age only the owned expiry; every assertion reads the public API.
		_, err = f.pool.Exec(ctx, "UPDATE "+aliases+" SET expires_at=now()-interval '1 microsecond' WHERE slug='old-brand'")
		noError(t, err)
		unresolved(t, "old-brand")
		claimant := create(t, "old-brand")
		resolves(t, "old-brand", claimant, "old-brand")
		resolves(t, "new-brand", old, "new-brand")

		immediate := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) {
			c.Tenants.FormerNames = authkit.FormerNamesConfig{Mode: authkit.FormerNamesImmediate}
		}))
		fleeting := create(t, "fleeting")
		_, err = immediate.RenameTenant(ctx, fleeting, "lasting")
		noError(t, err)
		unresolved(t, "fleeting")
		create(t, "fleeting")

		forever := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) {
			c.Tenants.FormerNames = authkit.FormerNamesConfig{Mode: authkit.FormerNamesForever}
		}))
		kept := create(t, "kept-name")
		_, err = forever.RenameTenant(ctx, kept, "kept-new")
		noError(t, err)
		var endless bool
		noError(t, f.pool.QueryRow(ctx, "SELECT expires_at IS NULL FROM "+aliases+" WHERE slug='kept-name'").Scan(&endless))
		if !endless {
			t.Fatal("a forever former name expires")
		}
	})

	t.Run("AK-J37-C05_concurrent_claims_of_one_name_have_one_winner", func(t *testing.T) {
		const racers = 8
		race := func(fn func(i int) error) []error {
			errs := make([]error, racers)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range racers {
				wg.Go(func() {
					<-start
					errs[i] = fn(i)
				})
			}
			close(start)
			wg.Wait()
			return errs
		}
		one := func(t *testing.T, errs []error) int {
			t.Helper()
			winner := -1
			for i, err := range errs {
				switch {
				case err == nil && winner < 0:
					winner = i
				case err == nil:
					t.Fatal("two tenants won one name")
				case !errors.Is(err, iam.ErrTenantNameTaken):
					t.Fatalf("racer %d: %v", i, err)
				}
			}
			if winner < 0 {
				t.Fatal("no tenant won the name")
			}
			return winner
		}
		ids := make([]iam.TenantID, racers)
		for i := range ids {
			ids[i] = iam.NewTenantID()
		}
		won := one(t, race(func(i int) error { return f.auth.CreateTenant(ctx, iam.Tenant{ID: ids[i], Slug: "contested"}) }))
		resolves(t, "contested", ids[won], "contested")

		names := make([]string, racers)
		for i := range ids {
			names[i] = "crowd-" + string(rune('a'+i))
			ids[i] = create(t, names[i])
		}
		won = one(t, race(func(i int) error { _, err := f.auth.RenameTenant(ctx, ids[i], "crowded"); return err }))
		resolves(t, "crowded", ids[won], "crowded")
		for i := range ids {
			if i != won {
				resolves(t, names[i], ids[i], names[i])
			}
		}

		// A name being vacated is never handed out: before the rename it is
		// live, after it a former name.
		for i := range ids {
			ids[i] = create(t, "vacated-"+string(rune('a'+i)))
		}
		errs := race(func(i int) error {
			if i%2 == 0 {
				_, err := f.auth.RenameTenant(ctx, ids[i], "moved-"+string(rune('a'+i)))
				return err
			}
			return f.auth.CreateTenant(ctx, iam.Tenant{ID: iam.NewTenantID(), Slug: "vacated-" + string(rune('a'+i-1))})
		})
		for i, err := range errs {
			if i%2 == 0 {
				noError(t, err)
				resolves(t, "vacated-"+string(rune('a'+i)), ids[i], "moved-"+string(rune('a'+i)))
			} else {
				isErr(t, err, iam.ErrTenantNameTaken)
			}
		}
	})

	t.Run("AK-J37-C06_http_tenant_directory_is_root_authorized", func(t *testing.T) {
		op, audit, outsider := f.user(t), f.user(t), f.user(t)
		authtest.GrantRole(t, f.auth, iam.RootGroup(), iam.UserSubject(op.ID), operator)
		authtest.GrantRole(t, f.auth, iam.RootGroup(), iam.UserSubject(audit.ID), auditor)
		opToken, auditToken, outsiderToken := f.signIn(t, op).AccessToken, f.signIn(t, audit).AccessToken, f.signIn(t, outsider).AccessToken
		id := iam.NewTenantID()
		body := map[string]any{"id": id.String(), "slug": "Web-Shop"}
		var created iam.Tenant
		r := f.call(t, "POST", "/admin/tenants", opToken, body)
		r.want(t, http.StatusCreated, "")
		decode(t, r.body, &created)
		if created.ID != id || created.Slug != "web-shop" || created.CreatedAt.IsZero() {
			t.Fatalf("created %s", r.body)
		}
		f.call(t, "POST", "/admin/tenants", opToken, body).want(t, http.StatusCreated, "")
		f.call(t, "POST", "/admin/tenants", opToken, map[string]any{"id": id.String(), "slug": "web-store"}).want(t, http.StatusConflict, "tenant_conflict")
		f.call(t, "POST", "/admin/tenants", opToken, map[string]any{"id": iam.NewTenantID().String(), "slug": "web-shop"}).want(t, http.StatusConflict, "tenant_name_taken")
		f.call(t, "POST", "/admin/tenants", opToken, map[string]any{"id": iam.NewTenantID().String(), "slug": "web_shop"}).want(t, http.StatusBadRequest, "invalid_tenant_slug")
		f.call(t, "POST", "/admin/tenants", opToken, map[string]any{"slug": "no-id"}).want(t, http.StatusBadRequest, "invalid_request")
		f.call(t, "POST", "/admin/tenants", opToken, map[string]any{"id": "not-a-uuid", "slug": "bad-id"}).want(t, http.StatusBadRequest, "invalid_request")

		r = f.call(t, "PATCH", "/admin/tenants/"+id.String(), opToken, map[string]any{"slug": "web-store"})
		r.want(t, http.StatusOK, "")
		var renamed iam.Tenant
		decode(t, r.body, &renamed)
		if renamed.ID != id || renamed.Slug != "web-store" || renamed.SlugChangedAt == nil {
			t.Fatalf("renamed %s", r.body)
		}
		f.call(t, "PATCH", "/admin/tenants/"+iam.NewTenantID().String(), opToken, map[string]any{"slug": "ghost"}).want(t, http.StatusNotFound, "not_found")
		f.call(t, "PATCH", "/admin/tenants/"+f.tenant.String(), opToken, map[string]any{"slug": "web-shop"}).want(t, http.StatusConflict, "tenant_name_taken")

		for _, path := range []string{"/admin/tenants/" + id.String(), "/admin/tenants/by-slug/web-shop", "/admin/tenants/by-slug/WEB-STORE"} {
			r = f.call(t, "GET", path, auditToken, nil)
			r.want(t, http.StatusOK, "")
			var got iam.Tenant
			decode(t, r.body, &got)
			native, err := f.auth.Tenant(ctx, id)
			noError(t, err)
			if got.ID != id || got.Slug != native.Slug || !got.SlugChangedAt.Equal(*native.SlugChangedAt) {
				t.Fatalf("GET %s = %s, native %+v", path, r.body, native)
			}
		}
		for _, path := range []string{"/admin/tenants/" + iam.NewTenantID().String(), "/admin/tenants/not-a-uuid", "/admin/tenants/by-slug/nobody", "/admin/tenants/by-slug/no_such"} {
			f.call(t, "GET", path, auditToken, nil).want(t, http.StatusNotFound, "not_found")
		}

		f.call(t, "POST", "/admin/tenants", auditToken, map[string]any{"id": iam.NewTenantID().String(), "slug": "audited"}).want(t, http.StatusForbidden, "")
		f.call(t, "PATCH", "/admin/tenants/"+id.String(), auditToken, map[string]any{"slug": "audited"}).want(t, http.StatusForbidden, "")
		for _, call := range []struct{ method, path string }{{"GET", "/admin/tenants/" + id.String()}, {"GET", "/admin/tenants/by-slug/web-store"}, {"POST", "/admin/tenants"}, {"PATCH", "/admin/tenants/" + id.String()}} {
			f.call(t, call.method, call.path, outsiderToken, map[string]any{"id": iam.NewTenantID().String(), "slug": "outsider"}).want(t, http.StatusForbidden, "")
			f.call(t, call.method, call.path, "", map[string]any{"id": iam.NewTenantID().String(), "slug": "anonymous"}).want(t, http.StatusUnauthorized, "")
		}
		unresolved(t, "audited")
		unresolved(t, "outsider")
		unresolved(t, "anonymous")
	})
}
