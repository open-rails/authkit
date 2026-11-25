package critical_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// unscoped leaves a fixture's deployment without DefaultTenantID.
var unscoped = authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{} })

// tenantIDs are the tenants in f's database.
func (f *fixture) tenantIDs(t *testing.T) []iam.TenantID {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), "SELECT id::text FROM "+pgx.Identifier{f.schema, "tenants"}.Sanitize()+" ORDER BY id")
	noError(t, err)
	ids, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (iam.TenantID, error) {
		var text string
		if err := row.Scan(&text); err != nil {
			return iam.TenantID{}, err
		}
		return iam.ParseTenantID(text)
	})
	noError(t, err)
	return ids
}

// rowCounts counts the rows of every table in f's schema.
func (f *fixture) rowCounts(t *testing.T) map[string]int64 {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT table_name::text,
		(xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text::bigint
		FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE'`, f.schema)
	noError(t, err)
	counts := map[string]int64{}
	for rows.Next() {
		var table string
		var n int64
		noError(t, rows.Scan(&table, &n))
		counts[table] = n
	}
	noError(t, rows.Err())
	return counts
}

func TestCriticalTenancy(t *testing.T) {
	t.Run("AK-J02-C08_single_tenant_database_makes_and_keeps_one_tenant", func(t *testing.T) {
		f := newFixture(t, unscoped)
		ids := f.tenantIDs(t)
		if len(ids) != 1 || ids[0][6]>>4 != 7 || f.auth.TenantID() != ids[0] {
			t.Fatalf("a fresh single-tenant database holds %v, want one UUIDv7 tenant the Client acts in (%s)", ids, f.auth.TenantID())
		}
		sole := ids[0]
		group, err := f.auth.Group(t.Context(), iam.GroupByID(sole.String()))
		noError(t, err)
		if group.Persona != iam.TenantPersona() || group.TenantID != sole {
			t.Fatalf("the tenant has no canonical group: %+v", group)
		}
		u := f.user(t)
		if u.TenantID != sole {
			t.Fatalf("an unscoped sign-up landed in %s, not the tenant %s", u.TenantID, sole)
		}
		f.signIn(t, u)

		// Restarts, explicit migrations and the tenant named explicitly keep it.
		noError(t, authkit.Migrate(t.Context(), f.pool, f.cfg.Database))
		noError(t, authkit.Migrate(t.Context(), f.pool, f.cfg.Database, authkit.MigrationOptions{LegacyTenantID: sole}))
		replica := authtest.Replica(t, f.auth)
		got, err := replica.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.TenantID != sole || replica.TenantID() != sole {
			t.Fatal("a restart lost the tenant")
		}
		if ids := f.tenantIDs(t); len(ids) != 1 || ids[0] != sole {
			t.Fatalf("restarts and migrations changed the tenants: %v", ids)
		}

		// A single-tenant host names no tenant, even its own.
		named := f.cfg
		named.DefaultTenantID = sole
		startRefused(t, named, f.deps, "DefaultTenantID is multi-tenant only")
	})

	t.Run("AK-J02-C09_single_tenant_adopts_the_one_tenant_a_database_holds", func(t *testing.T) {
		// An existing app's database: multi-tenant, one explicit tenant, accounts.
		f := newFixture(t, multiTenant)
		u := f.user(t)
		before := f.tenantIDs(t)
		noError(t, f.auth.Close(t.Context()))

		single := f.cfg
		single.Tenancy, single.DefaultTenantID = authkit.TenancySingle, iam.TenantID{}
		adopted, err := authkit.New(t.Context(), single, f.deps)
		noError(t, err)
		t.Cleanup(func() { noError(t, adopted.Close(context.Background())) })
		if adopted.TenantID() != f.tenant {
			t.Fatalf("adopted %s, not the database's tenant %s", adopted.TenantID(), f.tenant)
		}
		got, err := adopted.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if got.TenantID != f.tenant {
			t.Fatal("adoption moved an account")
		}
		groups, err := authkit.EnsureGroups(t.Context(), f.pool, single, []iam.NewGroup{{ID: iam.NewTenantID().String(), Persona: f.shop.Persona}}, nil)
		noError(t, err)
		if groups[0].TenantID != f.tenant {
			t.Fatalf("an unscoped configured group landed in %s", groups[0].TenantID)
		}

		single.DefaultTenantID = iam.NewTenantID()
		startRefused(t, single, f.deps, "DefaultTenantID is multi-tenant only")
		if after := f.tenantIDs(t); len(after) != 1 || after[0] != before[0] {
			t.Fatalf("adoption changed the tenants: %v", after)
		}
	})

	t.Run("AK-J02-C10_single_tenant_refuses_more_tenants", func(t *testing.T) {
		var operator iam.Role
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			operator = c.Roles.Root.Role("tenantcreator", c.Roles.Root.Tenants.Read, c.Roles.Root.Tenants.Manage)
		}))
		err := f.auth.CreateTenant(t.Context(), iam.Tenant{ID: iam.NewTenantID(), Slug: "second"})
		if !errors.Is(err, iam.ErrSingleTenant) || !strings.Contains(err.Error(), "TenancyMulti") {
			t.Fatalf("CreateTenant = %v, want ErrSingleTenant naming TenancyMulti", err)
		}
		op := f.user(t)
		authtest.GrantRole(t, f.auth, iam.RootGroup(), iam.UserSubject(op.ID), operator)
		fresh := f.signIn(t, op).AccessToken
		f.call(t, "POST", "/admin/tenants", fresh, map[string]any{"id": iam.NewTenantID().String(), "slug": "second"}).want(t, http.StatusForbidden, "single_tenant")
		if _, err := f.auth.ForTenant(t.Context(), iam.NewTenantID()); !errors.Is(err, iam.ErrSingleTenant) {
			t.Fatalf("ForTenant(another) = %v, want ErrSingleTenant", err)
		}
		view, err := f.auth.ForTenant(t.Context(), f.tenant)
		noError(t, err)
		if view.TenantID() != f.tenant {
			t.Fatal("the deployment's own tenant was not selectable")
		}
		// Matching provisioning of its own tenant stays a no-op; another name
		// for it is the conflict it always was.
		own, err := f.auth.Tenant(t.Context(), f.tenant)
		noError(t, err)
		noError(t, f.auth.CreateTenant(t.Context(), iam.Tenant{ID: f.tenant, Slug: own.Slug}))
		if err := f.auth.CreateTenant(t.Context(), iam.Tenant{ID: f.tenant, Slug: "renamed-by-create"}); !errors.Is(err, iam.ErrTenantConflict) {
			t.Fatalf("CreateTenant(own ID, another name) = %v, want ErrTenantConflict", err)
		}
		f.call(t, "POST", "/admin/tenants", fresh, map[string]any{"id": f.tenant.String(), "slug": own.Slug}).want(t, http.StatusCreated, "")
		if ids := f.tenantIDs(t); len(ids) != 1 {
			t.Fatalf("a single-tenant deployment holds %v", ids)
		}

		// A database with more tenants contradicts the mode: New and Migrate refuse it.
		m := newFixture(t, multiTenant)
		noError(t, m.auth.CreateTenant(t.Context(), iam.Tenant{ID: iam.NewTenantID(), Slug: "realm"}))
		cfg := m.cfg
		cfg.Tenancy, cfg.DefaultTenantID = authkit.TenancySingle, iam.TenantID{}
		startRefused(t, cfg, m.deps, "more than one tenant")
		if err := authkit.Migrate(t.Context(), m.pool, m.cfg.Database); err == nil || !strings.Contains(err.Error(), "more than one tenant") {
			t.Fatalf("single-tenant Migrate of two tenants = %v", err)
		}
		noError(t, authkit.Migrate(t.Context(), m.pool, m.cfg.Database, authkit.MigrationOptions{Tenancy: authkit.TenancyMulti}))
	})

	t.Run("AK-J02-C11_multi_tenant_without_a_default_writes_nothing_unscoped", func(t *testing.T) {
		f := newFixture(t, multiTenant, unscoped)
		if ids := f.tenantIDs(t); len(ids) != 0 || !f.auth.TenantID().IsZero() {
			t.Fatalf("a multi-tenant database got tenants it was never given: %v", ids)
		}
		before := f.rowCounts(t)
		in := iam.NewUser{Email: "unscoped@example.com", Username: "unscoped", Password: authtest.Password, EmailVerified: true}
		if _, err := f.auth.CreateUser(t.Context(), in); !errors.Is(err, iam.ErrTenantRequired) {
			t.Fatalf("unscoped CreateUser = %v", err)
		}
		if _, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: f.shop.Persona}); !errors.Is(err, iam.ErrTenantRequired) {
			t.Fatalf("unscoped CreateGroup = %v", err)
		}
		if _, err := authkit.EnsureGroups(t.Context(), f.pool, f.cfg, []iam.NewGroup{{ID: iam.NewTenantID().String(), Persona: f.shop.Persona}}, nil); !errors.Is(err, iam.ErrTenantRequired) {
			t.Fatalf("unscoped EnsureGroups = %v", err)
		}
		manifest := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Email: in.Email, Username: in.Username}}}
		if _, err := f.auth.ApplyBootstrapManifest(t.Context(), manifest, iam.BootstrapOptions{}); err == nil {
			t.Fatal("an unscoped bootstrap manifest applied")
		}
		for _, r := range []response{
			f.call(t, "POST", "/register", "", map[string]string{"identifier": in.Email, "username": in.Username, "password": authtest.Password}),
			f.call(t, "POST", "/password/login", "", map[string]string{"identifier": in.Email, "password": authtest.Password}),
		} {
			if r.status < 400 {
				t.Fatalf("an unscoped request succeeded: %d %s", r.status, r.body)
			}
		}
		after := f.rowCounts(t)
		for table, n := range after {
			if before[table] != n {
				t.Errorf("an unscoped operation wrote %s: %d rows, then %d", table, before[table], n)
			}
		}
	})

	t.Run("AK-J02-C12_a_single_tenant_host_names_no_tenant_for_its_SCIM_client_or_target", func(t *testing.T) {
		const secret = "a single-tenant directory reader's secret"
		sum := sha256.Sum256([]byte(secret))
		target := newSCIMTarget()
		as := authtest.NewAuthorizationServer(t, authtest.WithConfig(func(c *authkit.Config) {
			scim := strings.TrimRight(c.Issuer, "/") + "/scim/v2"
			c.AuthorizationServer.Clients = []authkit.OAuthClientConfig{{ID: "directory-reader", SecretSHA256: hex.EncodeToString(sum[:]), GrantTypes: []authkit.OAuthGrantType{authkit.GrantClientCredentials}, Resources: []string{scim}}}
			c.Provisioning = []authkit.ProvisioningTarget{{Name: "directory"}}
		}), authtest.WithDeps(func(d *authkit.Deps) { d.SCIMHandlers = map[string]http.Handler{"directory": target} }))
		u := authtest.NewUser(t, as.Client)
		if u.TenantID != as.Client.TenantID() || as.Client.TenantID().IsZero() {
			t.Fatalf("the account landed in %s, not the one tenant %s", u.TenantID, as.Client.TenantID())
		}
		// The client reads the one tenant's accounts.
		tokens := as.ClientCredentials(t, "directory-reader", secret, as.URL+"/scim/v2", []string{"scim:read"}, nil)
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, as.URL+"/scim/v2/Users/"+u.ID, nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		res, err := http.DefaultClient.Do(r)
		noError(t, err)
		defer res.Body.Close()
		var user struct {
			ID string `json:"id"`
		}
		if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&user) != nil || user.ID != u.ID {
			t.Fatalf("the single-tenant SCIM client read HTTP %d for %s", res.StatusCode, u.ID)
		}
		// The target receives the one tenant's accounts.
		noError(t, as.Client.Start(context.Background()))
		target.await(t, u.ID)
	})
}
