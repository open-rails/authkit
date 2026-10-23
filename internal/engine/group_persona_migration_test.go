package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type personaMigrationFixture struct {
	e                 *Engine
	in                iam.GroupPersonaMigration
	key               iam.APIKeyCreated
	user              string
	old, next         iam.Perm
	oldRole, nextRole iam.Role
	tenantRole        iam.Role
	tenantRead        iam.Perm
}

func newPersonaMigrationFixture(t *testing.T) personaMigrationFixture {
	t.Helper()
	cfg := testConfig()
	cfg.HTTP = &config.HTTPConfig{DirectPeerIP: true}
	roles := config.NewRoles(config.APIKeys, config.CustomRoles)
	options := []config.PersonaOption{config.APIKeys, config.CustomRoles, config.RemoteApplications, config.OAuthClients}
	old, next := roles.Persona("oldspace", options...), roles.Persona("workspace", options...)
	oldRead, nextRead := old.Permission("documents", "read"), next.Permission("documents", "read")
	oldRole, nextRole := old.Role("reader", oldRead), next.Role("reader", nextRead)
	tenantRead := roles.Tenant.Permission("documents", "read")
	tenantRole := roles.Tenant.Role("reader", tenantRead)
	roles.Root.Role("legacy-issuer", ident.CredentialsManage(ident.Persona("oldspace")), oldRead)
	roles.Root.Role("migration-issuer", ident.CredentialsManage(ident.Persona("oldspace")), oldRead, ident.CredentialsManage(ident.Persona("workspace")), nextRead)
	cfg.Roles = roles
	e := newPersonaMigrationEngine(t, cfg)
	g, err := e.CreateGroup(t.Context(), iam.NewGroup{Persona: ident.Persona("oldspace")})
	require.NoError(t, err)
	u := newUser(t, e, "migrating")
	_, err = e.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.GroupByID(g.ID), iam.UserSubject(u.ID), oldRole)
	require.NoError(t, err)
	key, err := e.CreateAPIKey(t.Context(), iam.SystemIdentity(), iam.GroupByID(g.ID), iam.NewAPIKey{Name: "retained", Role: oldRole})
	require.NoError(t, err)
	return personaMigrationFixture{e: e, key: key, user: u.ID, old: oldRead, next: nextRead, oldRole: oldRole, nextRole: nextRole, tenantRole: tenantRole, tenantRead: tenantRead,
		in: iam.GroupPersonaMigration{Group: iam.GroupByID(g.ID), From: g.Persona, To: ident.Persona("workspace"),
			Roles: map[iam.Role]iam.Role{oldRole: nextRole}, Permissions: map[iam.Perm]iam.Perm{oldRead: nextRead}}}
}

func newPersonaMigrationEngine(t *testing.T, cfg config.Config) *Engine {
	t.Helper()
	pool := testdb.UnlockedPool(t)
	schema := "persona_migration_" + uniqueSuffix()
	cfg.Database.Schema, cfg.Database.RiverSchema = schema, schema
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
		_, err = pool.Exec(ctx, "DELETE FROM public.migrations WHERE app='authkit' AND schema=$1", schema)
		require.NoError(t, err)
	})
	return newTestEngine(t, cfg, config.Deps{Postgres: pool})
}

func migrationEventCount(t *testing.T, f personaMigrationFixture) int {
	t.Helper()
	var count int
	require.NoError(t, f.e.pg.QueryRow(t.Context(), `SELECT count(*) FROM event_log WHERE kind=$1 AND payload->>'group_id'=$2`, string(iam.EventGroupPersonaMigrated), f.in.Group.ID()).Scan(&count))
	return count
}

func assertPersonaGuard(t *testing.T, f personaMigrationFixture, want iam.Persona) {
	t.Helper()
	ctx := t.Context()
	var enabled string
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger WHERE tgrelid='permission_groups'::regclass AND tgname='permission_group_identity_immutable'`).Scan(&enabled))
	require.Equal(t, "O", enabled)
	_, err := f.e.pg.Exec(ctx, `UPDATE permission_groups SET persona='forbidden' WHERE id=$1`, f.in.Group.ID())
	require.ErrorContains(t, err, "immutable")
	_, err = f.e.pg.Exec(ctx, `UPDATE permission_groups SET tenant_id=$2::uuid WHERE id=$1`, f.in.Group.ID(), iam.NewTenantID().String())
	require.ErrorContains(t, err, "immutable")
	g, err := f.e.Group(ctx, f.in.Group)
	require.NoError(t, err)
	require.Equal(t, want, g.Persona)
}

func TestGroupPersonaMigrationRetainsBindingsAndSecrets(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	custom, err := f.e.CreateGroupRole(ctx, iam.SystemIdentity(), f.in.Group, iam.NewGroupRole{Name: "helper", Permissions: []iam.Perm{f.old}})
	require.NoError(t, err)
	nextCustom := ident.Role(f.in.To, "custom-helper")
	f.in.Roles[custom.Name] = nextCustom
	other := newUser(t, f.e, "custom")
	_, err = f.e.SetGroupRole(ctx, iam.SystemIdentity(), f.in.Group, iam.UserSubject(other.ID), custom.Name)
	require.NoError(t, err)
	var appID, remoteID string
	require.NoError(t, f.e.pg.QueryRow(ctx, `INSERT INTO remote_applications(issuer,jwks_uri,permission_group_id,role_map) VALUES('https://migration.test','https://migration.test/jwks',$1,jsonb_build_object('reader',$2::text)) RETURNING id`, f.in.Group.ID(), f.oldRole.String()).Scan(&appID))
	_, err = f.e.pg.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,$3)`, f.in.Group.ID(), appID, f.oldRole.String())
	require.NoError(t, err)
	require.NoError(t, f.e.pg.QueryRow(ctx, `INSERT INTO remote_users(permission_group_id,issuer,subject) VALUES($1,'https://migration.test','member') RETURNING id`, f.in.Group.ID()).Scan(&remoteID))
	_, err = f.e.pg.Exec(ctx, `INSERT INTO group_remote_user_roles(permission_group_id,remote_user_id,role) VALUES($1,$2,$3)`, f.in.Group.ID(), remoteID, f.oldRole.String())
	require.NoError(t, err)
	_, err = f.e.pg.Exec(ctx, `INSERT INTO group_invite_links(permission_group_id,role,code_hash,tenant_id) VALUES($1,$2,'fixture-link-hash',$3)`, f.in.Group.ID(), f.oldRole.String(), f.e.cfg.DefaultTenantID.String())
	require.NoError(t, err)
	_, err = f.e.pg.Exec(ctx, `INSERT INTO account_registration_invites(email,permission_group_id,role,code_hash,expires_at,tenant_id) VALUES('migration@example.test',$1,$2,'fixture-invite-hash',now()+interval '1 day',$3)`, f.in.Group.ID(), f.oldRole.String(), f.e.cfg.DefaultTenantID.String())
	require.NoError(t, err)
	clientID := "goc_" + strings.Repeat("a", 26)
	_, err = f.e.pg.Exec(ctx, `INSERT INTO group_oauth_clients(client_id,permission_group_id,client_name,redirect_uris,token_endpoint_auth_method,scopes) VALUES($1,$2,'fixture',ARRAY['https://migration.test/callback'],'none',ARRAY['openid'])`, clientID, f.in.Group.ID())
	require.NoError(t, err)
	_, err = f.e.pg.Exec(ctx, `INSERT INTO oauth_consents(user_id,client_id,scopes) VALUES($1,$2,ARRAY['openid'])`, f.user, clientID)
	require.NoError(t, err)
	var secret []byte
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT secret_hash FROM api_keys WHERE id=$1`, f.key.APIKey.ID).Scan(&secret))
	before, err := f.e.ResolveAPIKey(ctx, f.key.Secret)
	require.NoError(t, err)
	require.Contains(t, before.Permissions, f.old)
	plan, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	require.False(t, plan.Applied)
	require.Zero(t, migrationEventCount(t, f))
	require.Len(t, plan.Fingerprint, 64)
	require.Equal(t, 2, plan.Counts["group_user_roles"])
	for _, kind := range []string{"api_keys", "group_remote_application_roles", "group_remote_user_roles", "group_invite_links", "account_registration_invites", "custom_roles", "oauth_clients", "oauth_consents"} {
		require.Equal(t, 1, plan.Counts[kind], kind)
	}
	assertPersonaGuard(t, f, f.in.From)
	f.in.Apply, f.in.ExpectedFingerprint = true, plan.Fingerprint
	applied, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	require.True(t, applied.Applied)
	require.Equal(t, 1, migrationEventCount(t, f))
	var eventTenant, eventPersona, previous, current, reason string
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT payload->>'tenant_id',payload->>'persona',payload->>'previous',payload->>'current',payload->>'reason' FROM event_log WHERE kind=$1 AND payload->>'group_id'=$2`, string(iam.EventGroupPersonaMigrated), f.in.Group.ID()).Scan(&eventTenant, &eventPersona, &previous, &current, &reason))
	require.Equal(t, applied.TenantID.String(), eventTenant)
	require.Equal(t, f.in.To.String(), eventPersona)
	require.Equal(t, f.in.From.String(), previous)
	require.Equal(t, f.in.To.String(), current)
	require.Empty(t, reason)
	assertPersonaGuard(t, f, f.in.To)
	after, err := f.e.ResolveAPIKey(ctx, f.key.Secret)
	require.NoError(t, err)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.Group.ID, after.Group.ID)
	require.Equal(t, f.nextRole, after.Role)
	require.Contains(t, after.Permissions, f.next)
	require.NotContains(t, after.Permissions, f.old)
	var preserved bool
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT secret_hash=$2::bytea AND revoked_at IS NULL FROM api_keys WHERE id=$1`, f.key.APIKey.ID, secret).Scan(&preserved))
	require.True(t, preserved, "secret and live status retained")
	var mapped string
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT role_map->>'reader' FROM remote_applications WHERE id=$1`, appID).Scan(&mapped))
	require.Equal(t, f.nextRole.String(), mapped)
	for _, query := range []string{
		`SELECT role FROM group_remote_user_roles WHERE remote_user_id=$1`,
		`SELECT role FROM group_remote_application_roles WHERE remote_application_id=$1`,
	} {
		id := remoteID
		if strings.Contains(query, "application") {
			id = appID
		}
		require.NoError(t, f.e.pg.QueryRow(ctx, query, id).Scan(&mapped))
		require.Equal(t, f.nextRole.String(), mapped)
	}
	customAfter, err := f.e.GroupRole(ctx, f.in.Group, nextCustom)
	require.NoError(t, err)
	require.Equal(t, []iam.Perm{f.next}, customAfter.Permissions)
	redone, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	require.True(t, redone.AlreadyTarget)
	require.False(t, redone.Applied)
	require.Equal(t, 1, migrationEventCount(t, f))
	raw, err := json.Marshal(redone)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(raw), f.key.Secret), "report leaked a credential")
}

func TestGroupPersonaMigrationRefusesStaleOrExpandedPlan(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	unmapped := f.in
	unmapped.Roles = nil
	_, err := f.e.MigrateGroupPersona(ctx, unmapped)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	plan, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	other := newUser(t, f.e, "changed")
	_, err = f.e.SetGroupRole(ctx, iam.SystemIdentity(), f.in.Group, iam.UserSubject(other.ID), f.oldRole)
	require.NoError(t, err)
	f.in.Apply, f.in.ExpectedFingerprint = true, plan.Fingerprint
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaFingerprint)
	assertPersonaGuard(t, f, f.in.From)
	f.in.Apply = false
	f.in.Roles[f.oldRole] = f.in.To.OwnerRole()
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	f.in.From = iam.RootPersona()
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	f.in.From = ident.Persona("oldspace")
	f.in.To = iam.RootPersona()
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
}

func TestGroupPersonaMigrationFailureRestoresEveryGuard(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	plan, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	_, err = f.e.pg.Exec(ctx, `CREATE FUNCTION migration_injected_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected migration failure'; END $$; CREATE TRIGGER migration_injected_failure BEFORE UPDATE OF role ON api_keys FOR EACH ROW EXECUTE FUNCTION migration_injected_failure()`)
	require.NoError(t, err)
	f.in.Apply, f.in.ExpectedFingerprint = true, plan.Fingerprint
	report, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorContains(t, err, "injected migration failure")
	require.False(t, report.Applied)
	require.Zero(t, migrationEventCount(t, f))
	assertPersonaGuard(t, f, f.in.From)
	roles, err := f.e.GroupRoles(ctx, f.in.Group, []iam.Subject{iam.UserSubject(f.user)})
	require.NoError(t, err)
	require.Equal(t, f.oldRole, roles[iam.UserSubject(f.user)])
	_, err = f.e.pg.Exec(ctx, `DROP TRIGGER migration_injected_failure ON api_keys; DROP FUNCTION migration_injected_failure()`)
	require.NoError(t, err)
	_, err = f.e.MigrateGroupPersona(context.Background(), f.in)
	require.NoError(t, err)
	assertPersonaGuard(t, f, f.in.To)
}

func TestGroupPersonaMigrationKeepsIssuerCoverage(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	creator := newUser(t, f.e, "issuer")
	_, err := f.e.SetGroupRole(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(creator.ID), ident.Role(iam.RootPersona(), "legacy-issuer"))
	require.NoError(t, err)
	key, err := f.e.CreateAPIKey(ctx, iam.UserIdentity(creator.ID), f.in.Group, iam.NewAPIKey{Name: "issued", Role: f.oldRole})
	require.NoError(t, err)
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err, "organization key migration does not require its historical creator's authority")
	_, err = f.e.ResolveAPIKey(ctx, key.Secret)
	require.NoError(t, err, "dry-run must not revoke a key")
	_, err = f.e.SetGroupRole(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(creator.ID), ident.Role(iam.RootPersona(), "migration-issuer"))
	require.NoError(t, err)
	plan, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	f.in.Apply, f.in.ExpectedFingerprint = true, plan.Fingerprint
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.NoError(t, err)
	resolved, err := f.e.ResolveAPIKey(ctx, key.Secret)
	require.NoError(t, err)
	require.Equal(t, f.nextRole, resolved.Role)
}

func TestGroupPersonaMigrationHonorsCanonicalTenantAndBoundView(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	_, err := f.e.MigrateGroupPersona(WithTenant(ctx, iam.NewTenantID()), f.in)
	require.ErrorIs(t, err, iam.ErrTenantMismatch)
	noncanonical := f.in
	noncanonical.To = iam.TenantPersona()
	noncanonical.Roles = map[iam.Role]iam.Role{f.oldRole: f.tenantRole}
	noncanonical.Permissions = map[iam.Perm]iam.Perm{f.old: f.tenantRead}
	_, err = f.e.MigrateGroupPersona(ctx, noncanonical)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	canonicalID := f.e.cfg.DefaultTenantID.String()
	// Model the persisted old persona after explicit legacy-tenant adoption.
	// Only this isolated fixture uses the owner-level trigger transition.
	_, err = f.e.pg.Exec(ctx, `ALTER TABLE permission_groups DISABLE TRIGGER permission_group_identity_immutable; INSERT INTO permission_groups(id,persona,tenant_id) VALUES('`+canonicalID+`','oldspace','`+canonicalID+`') ON CONFLICT(id) DO UPDATE SET persona='oldspace'; ALTER TABLE permission_groups ENABLE TRIGGER permission_group_identity_immutable`)
	require.NoError(t, err)
	canonical := noncanonical
	canonical.Group = iam.GroupByID(canonicalID)
	plan, err := f.e.MigrateGroupPersona(ctx, canonical)
	require.NoError(t, err)
	canonical.Apply, canonical.ExpectedFingerprint = true, plan.Fingerprint
	_, err = f.e.MigrateGroupPersona(ctx, canonical)
	require.NoError(t, err)
	_, err = f.e.MigrateGroupPersona(ctx, iam.GroupPersonaMigration{Group: canonical.Group, From: iam.TenantPersona(), To: ident.Persona("workspace")})
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
}

func TestGroupPersonaMigrationRejectsForeignCatalogAndMFAChanges(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	_, err := f.e.pg.Exec(ctx, `UPDATE api_keys SET catalog_issuer='https://foreign.example.test' WHERE id=$1`, f.key.APIKey.ID)
	require.NoError(t, err)
	plan, err := f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	require.Contains(t, plan.Issuers, "https://foreign.example.test")
	assertPersonaGuard(t, f, f.in.From)

	cfg := testConfig()
	roles := config.NewRoles()
	old, next := roles.Persona("protected"), roles.Persona("replacement")
	p, q := old.Permission("data", "write"), next.Permission("data", "write")
	old.RequireMFA(p)
	before, after := old.Role("writer", p), next.Role("writer", q)
	cfg.Roles = roles
	e := newPersonaMigrationEngine(t, cfg)
	g, err := e.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("protected")})
	require.NoError(t, err)
	_, err = e.MigrateGroupPersona(ctx, iam.GroupPersonaMigration{Group: iam.GroupByID(g.ID), From: g.Persona, To: ident.Persona("replacement"), Roles: map[iam.Role]iam.Role{before: after}, Permissions: map[iam.Perm]iam.Perm{p: q}})
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	require.ErrorContains(t, err, "MFA")
}

func TestGroupPersonaMigrationHistoricalNativeOwnership(t *testing.T) {
	tenant, foreign := iam.NewTenantID(), iam.NewTenantID()
	meta := func(id iam.TenantID) json.RawMessage {
		raw, err := json.Marshal(map[string]iam.TenantID{"tenant_id": id})
		require.NoError(t, err)
		return raw
	}
	require.NoError(t, personaNativeOwners(tenant, []personaBinding{{Kind: "group_user_roles", Meta: meta(tenant)}}))
	require.ErrorIs(t, personaNativeOwners(tenant, []personaBinding{{Kind: "group_user_roles", Meta: meta(foreign)}}), iam.ErrGroupPersonaMigration)
	require.ErrorIs(t, personaNativeOwners(tenant, []personaBinding{{Kind: "group_user_roles"}}), iam.ErrGroupPersonaMigration)
	// A remote identity is not a native account in this tenant. Its authority
	// is checked through the application's binding and role instead.
	require.NoError(t, personaNativeOwners(tenant, []personaBinding{{Kind: "group_remote_user_roles", Meta: meta(foreign)}}))
}

func TestGroupPersonaMigrationRefusesRestoredForeignAssignment(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	ctx := t.Context()
	tenant := iam.NewTenantID()
	require.NoError(t, f.e.CreateTenant(ctx, iam.Tenant{ID: tenant}))
	user, err := f.e.createUser(WithTenant(ctx, tenant), uniqueEmail("foreign"), "foreign"+uniqueSuffix())
	require.NoError(t, err)
	_, err = f.e.pg.Exec(ctx, `INSERT INTO group_user_roles(permission_group_id,user_id,role) VALUES($1,$2,$3)`, f.in.Group.ID(), user.ID, f.oldRole.String())
	require.Error(t, err, "current writes must enforce tenant ownership")
	table := pgx.Identifier{f.e.dbSchema(), "group_user_roles"}.Sanitize()
	tx, err := f.e.pg.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	// Model a restored pre-constraint row in this isolated schema, then restore
	// the guard before asking the production migration to inspect it.
	_, err = tx.Exec(ctx, "ALTER TABLE "+table+" DISABLE TRIGGER group_user_tenant_owner")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO group_user_roles(permission_group_id,user_id,role) VALUES($1,$2,$3)`, f.in.Group.ID(), user.ID, f.oldRole.String())
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "ALTER TABLE "+table+" ENABLE TRIGGER group_user_tenant_owner")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	_, err = f.e.MigrateGroupPersona(ctx, f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	require.ErrorContains(t, err, "another tenant")
	var present bool
	require.NoError(t, f.e.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_user_roles WHERE permission_group_id=$1 AND user_id=$2)`, f.in.Group.ID(), user.ID).Scan(&present))
	require.True(t, present)
	require.Zero(t, migrationEventCount(t, f))
}

func TestGroupPersonaMigrationRefusesUnknownCustomGrant(t *testing.T) {
	f := newPersonaMigrationFixture(t)
	oldCustom, nextCustom := ident.Role(f.in.From, "custom-legacy"), ident.Role(f.in.To, "custom-legacy")
	_, err := f.e.pg.Exec(t.Context(), `INSERT INTO group_custom_roles(permission_group_id,role,permissions) VALUES($1,$2,$3)`, f.in.Group.ID(), oldCustom.String(), []string{f.old.String(), "oldspace:removed:write"})
	require.NoError(t, err)
	f.in.Roles[oldCustom] = nextCustom
	_, err = f.e.MigrateGroupPersona(t.Context(), f.in)
	require.ErrorIs(t, err, iam.ErrGroupPersonaMigration)
	require.ErrorContains(t, err, "unknown or invalid")
	assertPersonaGuard(t, f, f.in.From)
}
