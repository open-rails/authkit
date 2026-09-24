package embedded

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type groupQueryCounter struct{ n atomic.Int64 }

func (c *groupQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "permission_groups") {
		c.n.Add(1)
	}
	return ctx
}

func (c *groupQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (c *groupQueryCounter) during(t *testing.T, fn func()) int64 {
	t.Helper()
	before := c.n.Load()
	fn()
	return c.n.Load() - before
}

// A listing resolves many groups and one subject's permissions on them in two
// calls and two queries, identical to the single-group reads.
func TestBatchGroupReadsMatchSingleGroupReads(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	counter := &groupQueryCounter{}
	poolConfig := pg.Pool.Config()
	poolConfig.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := maintenanceConfig()
	cfg.Keys = KeysConfig{AllowEphemeralDevKeys: true}
	cfg.Token.ExpectedAudiences = []string{"test"}
	cfg.RBAC = []PersonaDef{
		{Name: RootPersona},
		{Name: "channel", Parent: RootPersona, Capabilities: PersonaCapabilities{CustomRoles: true},
			Catalog: []string{"channel:posts:read", "channel:posts:write"},
			Roles: []RoleDef{
				{Name: "reader", Permissions: []string{"channel:posts:read"}},
				{Name: "moderator", Permissions: []string{"channel:posts:read", "channel:posts:write"}, RequiresMFA: true},
			}},
		{Name: "section", Parent: "channel", Roles: []RoleDef{{Name: "editor", Permissions: []string{"section:pages:write"}}}},
	}
	rt, err := New(cfg, Deps{Postgres: pool})
	require.NoError(t, err)
	t.Cleanup(rt.Close)
	client := rt.Client()

	owner, err := client.CreateUser(ctx, "batch-owner@example.test", "batch-owner")
	require.NoError(t, err)
	member, err := client.CreateUser(ctx, "batch-member@example.test", "batch-member")
	require.NoError(t, err)
	subject := authkit.UserSubject(member.ID)
	create := func(persona authkit.Persona, slug, parent string) (string, authkit.GroupRef) {
		req := authkit.CreatePermissionGroupRequest{Persona: persona, InstanceSlug: slug, OwnerSubjectID: owner.ID}
		if parent != "" {
			req.ParentPersona, req.ParentInstanceSlug = "channel", parent
		}
		id, err := client.CreatePermissionGroup(ctx, req)
		require.NoError(t, err)
		return id, authkit.GroupRef{Persona: persona, Instance: slug}
	}
	assign := func(ref authkit.GroupRef, role authkit.Role) {
		require.NoError(t, client.OperatorAssignGroupRole(ctx, ref, subject, role))
	}

	reader, readerRef := create("channel", "batch-reader", "")
	assign(readerRef, "reader")
	moderated, moderatedRef := create("channel", "batch-moderated", "")
	assign(moderatedRef, "moderator")
	section, sectionRef := create("section", "batch-section", "batch-moderated")
	assign(sectionRef, "editor")
	curated, curatedRef := create("channel", "batch-curated", "")
	require.NoError(t, rt.engine.DefineGroupCustomRole(ctx, owner.ID, curatedRef, authkit.CustomRoleDef{Role: "curator", Permissions: []string{"channel:posts:write"}}))
	assign(curatedRef, "curator")
	retired, retiredRef := create("channel", "batch-retired", "")
	assign(retiredRef, "reader")
	_, err = client.SoftDeleteGroupInstanceByID(ctx, retired)
	require.NoError(t, err)
	unassigned, unassignedRef := create("channel", "batch-unassigned", "")
	unknown := uuid.NewString()

	ids := []string{reader, moderated, section, curated, retired, unassigned, unknown, "not-a-uuid", reader}
	refs := map[string]authkit.GroupRef{reader: readerRef, moderated: moderatedRef, section: sectionRef, curated: curatedRef, retired: retiredRef, unassigned: unassignedRef}

	var instances map[string]authkit.GroupInstance
	require.EqualValues(t, 1, counter.during(t, func() {
		instances, err = client.GroupInstancesByIDs(ctx, ids)
	}))
	require.NoError(t, err)
	require.Len(t, instances, 6)
	require.NotNil(t, instances[retired].DeletedAt)
	require.Nil(t, instances[reader].DeletedAt)
	for id := range refs {
		single, err := client.GroupInstanceByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, single, instances[id])
	}
	_, err = client.GroupInstanceByID(ctx, unknown)
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)

	var perms map[string][]authkit.Perm
	require.EqualValues(t, 1, counter.during(t, func() {
		perms, err = client.EffectivePermissionsForGroups(ctx, subject, ids)
	}))
	require.NoError(t, err)
	want := map[string][]authkit.Perm{
		reader:    {"channel:posts:read"},
		moderated: {"channel:posts:read", "channel:posts:write"},
		section:   {"channel:posts:read", "channel:posts:write", "section:pages:write"},
		curated:   {"channel:posts:write"},
	}
	require.Len(t, perms, len(want))
	for id, grants := range want {
		require.ElementsMatch(t, grants, perms[id])
	}
	for id, ref := range refs {
		single, err := client.ListEffectivePermissions(ctx, subject, ref)
		require.NoError(t, err)
		require.ElementsMatch(t, single, perms[id], "group %s", ref.Instance)
		for _, perm := range []authkit.Perm{"channel:posts:read", "channel:posts:write", "section:pages:write"} {
			allowed, err := client.CanOnGroup(ctx, subject, id, perm)
			require.NoError(t, err)
			covered := false
			for _, grant := range perms[id] {
				covered = covered || perm.Matches(grant)
			}
			require.Equal(t, covered, allowed, "%s on %s", perm, ref.Instance)
		}
	}

	ownerPerms, err := client.EffectivePermissionsForGroups(ctx, authkit.UserSubject(owner.ID), ids)
	require.NoError(t, err)
	require.NotContains(t, ownerPerms, retired)
	for _, id := range []string{reader, section, unassigned} {
		single, err := client.ListEffectivePermissions(ctx, authkit.UserSubject(owner.ID), refs[id])
		require.NoError(t, err)
		require.NotEmpty(t, single)
		require.ElementsMatch(t, single, ownerPerms[id])
	}

	empty, err := client.EffectivePermissionsForGroups(ctx, subject, nil)
	require.NoError(t, err)
	require.Empty(t, empty)
	tooMany := make([]string, authkit.MaxGroupBatch+1)
	for i := range tooMany {
		tooMany[i] = uuid.NewString()
	}
	_, err = client.GroupInstancesByIDs(ctx, tooMany)
	require.Error(t, err)
	_, err = client.EffectivePermissionsForGroups(ctx, subject, tooMany)
	require.Error(t, err)
}
