package engine

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
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
	cfg.Roles = RoleConfig{
		Personas: map[string]Persona{
			"channel": {Permissions: []string{"channel:posts:read", "channel:posts:write"}, CustomRoles: true},
			"section": {Permissions: []string{"section:pages:write"}},
		},
		Roles: []Role{
			{Persona: "channel", Name: "reader", Permissions: []string{"channel:posts:read"}},
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:write"}, Includes: []string{"reader"}},
			{Persona: "section", Name: "editor", Permissions: []string{"section:pages:write"}},
		},
	}
	rt, err := New(context.Background(), cfg, Deps{Postgres: pool})
	require.NoError(t, err)
	t.Cleanup(rt.Close)
	client := rt

	owner, err := client.createUser(ctx, "batch-owner@example.test", "batch-owner")
	require.NoError(t, err)
	member, err := client.createUser(ctx, "batch-member@example.test", "batch-member")
	require.NoError(t, err)
	subject := iam.UserSubject(member.ID)
	actor := iam.UserActor(member.ID)
	create := func(persona iam.Persona) (string, iam.GroupRef) {
		id, err := seedGroup(ctx, client, persona, owner.ID)
		require.NoError(t, err)
		return id, iam.GroupByID(id)
	}
	assign := func(ref iam.GroupRef, role string) {
		grantRole(t, client, ref, subject, role)
	}

	reader, readerRef := create(ident.Persona("channel"))
	assign(readerRef, "reader")
	moderated, moderatedRef := create(ident.Persona("channel"))
	assign(moderatedRef, "moderator")
	section, sectionRef := create(ident.Persona("section"))
	assign(sectionRef, "editor")
	curated, curatedRef := create(ident.Persona("channel"))
	require.NoError(t, defineRole(rt, ctx, iam.UserActor(owner.ID), curatedRef, "curator", []string{"channel:posts:write"}))
	assign(curatedRef, "curator")
	retired, retiredRef := create(ident.Persona("channel"))
	assign(retiredRef, "reader")
	require.NoError(t, client.DeleteGroup(ctx, iam.GroupByID(retired), nil))
	unassigned, unassignedRef := create(ident.Persona("channel"))
	unknown := uuid.NewString()

	ids := []string{reader, moderated, section, curated, retired, unassigned, unknown, "not-a-uuid", reader}
	refs := map[string]iam.GroupRef{reader: readerRef, moderated: moderatedRef, section: sectionRef, curated: curatedRef, retired: retiredRef, unassigned: unassignedRef}
	byID := make([]iam.GroupRef, 0, len(ids))
	for _, id := range ids {
		byID = append(byID, iam.GroupByID(id))
	}

	var instances map[string]iam.Group
	require.EqualValues(t, 1, counter.during(t, func() {
		instances, err = client.Groups(ctx, ids)
	}))
	require.NoError(t, err)
	require.Len(t, instances, 6)
	require.NotNil(t, instances[retired].DeletedAt)
	require.Nil(t, instances[reader].DeletedAt)
	for id := range refs {
		single, err := client.Group(ctx, iam.GroupByID(id))
		require.NoError(t, err)
		require.Equal(t, single, instances[id])
	}
	_, err = client.Group(ctx, iam.GroupByID(unknown))
	require.ErrorIs(t, err, iam.ErrGroupNotFound)

	var perms map[string][]iam.Perm
	require.EqualValues(t, 1, counter.during(t, func() {
		perms, err = client.EffectivePermissions(ctx, actor, byID)
	}))
	require.NoError(t, err)
	want := map[string][]iam.Perm{
		reader:    {ident.Perm("channel:posts:read")},
		moderated: {ident.Perm("channel:posts:read"), ident.Perm("channel:posts:write")},
		section:   {ident.Perm("section:pages:write")},
		curated:   {ident.Perm("channel:posts:write")},
	}
	require.Len(t, perms, len(want))
	for id, grants := range want {
		require.ElementsMatch(t, grants, perms[id])
	}
	for id, ref := range refs {
		single, err := effectivePermissions(ctx, client, actor, ref)
		require.NoError(t, err)
		require.ElementsMatch(t, single, perms[id], "group %s", ref)
		for _, perm := range []iam.Perm{ident.Perm("channel:posts:read"), ident.Perm("channel:posts:write"), ident.Perm("section:pages:write")} {
			allowed, err := client.Can(ctx, actor, iam.GroupByID(id), perm)
			require.NoError(t, err)
			covered := false
			for _, grant := range perms[id] {
				covered = covered || perm.Matches(grant)
			}
			require.Equal(t, covered, allowed, "%s on %s", perm, ref)
		}
	}

	ownerPerms, err := client.EffectivePermissions(ctx, iam.UserActor(owner.ID), byID)
	require.NoError(t, err)
	require.NotContains(t, ownerPerms, retired)
	for _, id := range []string{reader, section, unassigned} {
		single, err := effectivePermissions(ctx, client, iam.UserActor(owner.ID), refs[id])
		require.NoError(t, err)
		require.NotEmpty(t, single)
		require.ElementsMatch(t, single, ownerPerms[id])
	}

	empty, err := client.EffectivePermissions(ctx, actor, nil)
	require.NoError(t, err)
	require.Empty(t, empty)
	tooMany := make([]string, iam.MaxBatch+1)
	tooManyRefs := make([]iam.GroupRef, iam.MaxBatch+1)
	for i := range tooMany {
		tooMany[i] = uuid.NewString()
		tooManyRefs[i] = iam.GroupByID(tooMany[i])
	}
	_, err = client.Groups(ctx, tooMany)
	require.Error(t, err)
	_, err = client.EffectivePermissions(ctx, actor, tooManyRefs)
	require.Error(t, err)
}
