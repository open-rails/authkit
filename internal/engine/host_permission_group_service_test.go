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
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/helpers/auth"
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
// calls and two queries, identical to the single-group reads; past
// iam.MaxBatch groups, in a query per batch.
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
	cfg.Keys = config.KeysConfig{AllowEphemeralDevKeys: true}
	cfg.Token.ExpectedAudiences = []string{"test"}
	roles := config.NewRoles()
	channelDef, sectionDef := roles.Persona("channel"), roles.Persona("section")
	postsRead, postsWrite := channelDef.Permission("posts", "read"), channelDef.Permission("posts", "write")
	channelDef.Role("moderator", postsWrite, channelDef.Role("reader", postsRead))
	channelDef.Role("curator", postsWrite)
	sectionDef.Role("editor", sectionDef.Permission("pages", "write"))
	cfg.Roles = roles
	rt, err := New(context.Background(), cfg, config.Deps{Postgres: pool})
	require.NoError(t, err)
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	client := rt

	owner, err := client.createUser(ctx, "batch-owner@example.test", "batch-owner")
	require.NoError(t, err)
	member, err := client.createUser(ctx, "batch-member@example.test", "batch-member")
	require.NoError(t, err)
	subject := iam.UserSubject(member.ID)
	who := iam.UserIdentity(member.ID)
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
	assign(curatedRef, "curator")
	retired, retiredRef := create(ident.Persona("channel"))
	assign(retiredRef, "reader")
	require.NoError(t, client.DeleteGroup(ctx, iam.GroupByID(retired)))
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
		perms, err = client.EffectivePermissions(ctx, who, byID)
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
		single, err := effectivePermissions(ctx, client, who, ref)
		require.NoError(t, err)
		require.ElementsMatch(t, single, perms[id], "group %s", ref)
		for _, perm := range []iam.Perm{ident.Perm("channel:posts:read"), ident.Perm("channel:posts:write"), ident.Perm("section:pages:write")} {
			allowed, err := client.Can(ctx, who, iam.GroupByID(id), perm)
			require.NoError(t, err)
			covered := false
			for _, grant := range perms[id] {
				covered = covered || perm.Matches(grant)
			}
			require.Equal(t, covered, allowed, "%s on %s", perm, ref)
		}
	}

	ownerPerms, err := client.EffectivePermissions(ctx, iam.UserIdentity(owner.ID), byID)
	require.NoError(t, err)
	require.NotContains(t, ownerPerms, retired)
	for _, id := range []string{reader, section, unassigned} {
		single, err := effectivePermissions(ctx, client, iam.UserIdentity(owner.ID), refs[id])
		require.NoError(t, err)
		require.NotEmpty(t, single)
		require.ElementsMatch(t, single, ownerPerms[id])
	}

	empty, err := client.EffectivePermissions(ctx, who, nil)
	require.NoError(t, err)
	require.Empty(t, empty)

	// Past iam.MaxBatch ids, the reads take a query per batch.
	many := make([]string, iam.MaxBatch, iam.MaxBatch+len(ids))
	for i := range many {
		many[i] = uuid.NewString()
	}
	many = append(many, ids...)
	manyRefs := make([]iam.GroupRef, len(many))
	for i, id := range many {
		manyRefs[i] = iam.GroupByID(id)
	}
	require.EqualValues(t, 2, counter.during(t, func() {
		batched, err := client.Groups(ctx, many)
		require.NoError(t, err)
		require.Equal(t, instances, batched)
	}))
	require.EqualValues(t, 2, counter.during(t, func() {
		batched, err := client.EffectivePermissions(ctx, who, manyRefs)
		require.NoError(t, err)
		require.Equal(t, perms, batched)
	}))
}

// effectivePermissions is the identity's effective grants in one group.
func effectivePermissions(ctx context.Context, e *Engine, a auth.Identity, ref iam.GroupRef) ([]iam.Perm, error) {
	byGroup, err := e.EffectivePermissions(ctx, a, []iam.GroupRef{ref})
	if err != nil {
		return nil, err
	}
	for _, perms := range byGroup {
		return perms, nil
	}
	return []iam.Perm{}, nil
}
