package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func groupsTestEngine(t *testing.T, mode iam.TwoFactorMode, roles RoleConfig) *Engine {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	return mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://groups.test"}, TwoFactor: TwoFactorConfig{Mode: mode}, Roles: roles}, keyset{}, Deps{Postgres: pg.Pool})
}

func newGroupsUser(t *testing.T, e *Engine, name string) string {
	t.Helper()
	u, err := e.createUser(t.Context(), name+"@groups.test", name)
	require.NoError(t, err)
	return u.ID
}

// The group operations end to end: create, read, list, update, delete and
// purge, members and memberships, and live checks for every actor kind.
func TestGroupOperationsWorkflow(t *testing.T) {
	e := groupsTestEngine(t, iam.TwoFactorDisabled, RoleConfig{
		Personas: map[string]Persona{
			"channel": {Permissions: []string{"channel:posts:edit"}, APIKeys: true, CustomRoles: true,
				Creation: GroupCreation{Enabled: true, ReservedSlugs: []string{"announcements"}}},
			"org": {Permissions: []string{"org:records:read"}},
		},
		Roles: []Role{
			{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"channel:*"}},
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:edit", "channel:members:read"}},
			{Persona: "channel", Name: "janitor", Permissions: []string{"channel:self:delete"}},
		},
	})
	ctx := t.Context()
	bob, carol, dave, erin, admin := newGroupsUser(t, e, "gbob"), newGroupsUser(t, e, "gcarol"), newGroupsUser(t, e, "gdave"), newGroupsUser(t, e, "gerin"), newGroupsUser(t, e, "gadmin")
	grantRole(t, e, iam.RootGroup(), iam.UserSubject(admin), "admin")

	// A user creates a group and owns it; a re-run by the owner returns it.
	golang, created, err := e.CreateGroup(ctx, iam.UserActor(bob), iam.NewGroup{Persona: "channel", Slug: "Golang", DisplayName: "Go"})
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, iam.Group{ID: golang.ID, Persona: "channel", Slug: "golang", DisplayName: "Go"}, golang)
	again, created, err := e.CreateGroup(ctx, iam.UserActor(bob), iam.NewGroup{Persona: "channel", Slug: "golang"})
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, golang.ID, again.ID)
	_, _, err = e.CreateGroup(ctx, iam.UserActor(carol), iam.NewGroup{Persona: "channel", Slug: "golang"})
	require.ErrorIs(t, err, iam.ErrGroupSlugTaken)
	_, _, err = e.CreateGroup(ctx, iam.UserActor(carol), iam.NewGroup{Persona: "channel", Slug: "announcements"})
	require.ErrorIs(t, err, iam.ErrGroupSlugReserved)
	announcements, created, err := e.CreateGroup(ctx, iam.UserActor(admin), iam.NewGroup{Persona: "channel", Slug: "announcements"})
	require.NoError(t, err)
	require.True(t, created, "channel:* on root takes a reserved slug")
	_, _, err = e.CreateGroup(ctx, iam.UserActor(carol), iam.NewGroup{Persona: "org", Slug: "acme"})
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona, "org has no user creation")
	gift := iam.UserSubject(carol)
	_, _, err = e.CreateGroup(ctx, iam.UserActor(bob), iam.NewGroup{Persona: "channel", Slug: "gift", Owner: &gift})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "a user cannot make someone else an owner")
	_, _, err = e.CreateGroup(ctx, iam.Actor{}, iam.NewGroup{Persona: "channel", Slug: "anonymous"})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	acme, created, err := e.CreateGroup(ctx, iam.NewGroup{Persona: "org", Slug: "acme"})
	require.NoError(t, err)
	require.True(t, created, "the system creates any persona's group, with or without an owner")
	for _, slug := range []string{"rust", "python"} {
		_, err := seedGroup(ctx, e, "channel", slug, "")
		require.NoError(t, err)
	}
	golangRef := iam.GroupByID(golang.ID)
	key, _, err := e.MintAPIKey(ctx, iam.UserActor(bob), golangRef, iam.NewAPIKey{Name: "bot", Role: "moderator"})
	require.NoError(t, err)
	_, _, err = e.CreateGroup(ctx, iam.APIKeyActor(key.ID), iam.NewGroup{Persona: "channel", Slug: "robots"})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "machine actors cannot create groups")

	// Reads.
	for _, ref := range []iam.GroupRef{iam.GroupBySlug("channel", "golang"), golangRef} {
		got, err := e.Group(ctx, ref)
		require.NoError(t, err)
		require.Equal(t, golang, got)
	}
	root, err := e.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona, root.Persona)
	for _, ref := range []iam.GroupRef{iam.GroupBySlug("channel", "missing"), iam.GroupByID("not-a-uuid"), iam.GroupByID(uuid.NewString()), {}} {
		_, err = e.Group(ctx, ref)
		require.ErrorIs(t, err, iam.ErrGroupNotFound)
	}
	batch, err := e.Groups(ctx, []string{golang.ID, acme.ID, uuid.NewString(), golang.ID})
	require.NoError(t, err)
	require.Equal(t, map[string]iam.Group{golang.ID: golang, acme.ID: acme}, batch)

	// Lists page by slug.
	slugs := func(q iam.GroupQuery) []string {
		t.Helper()
		var out []string
		for {
			page, err := e.ListGroups(ctx, q)
			require.NoError(t, err)
			for _, g := range page.Items {
				out = append(out, g.Slug)
			}
			if page.Next == "" {
				return out
			}
			q.Page.Cursor = page.Next
		}
	}
	require.Equal(t, []string{"announcements", "golang", "python", "rust"}, slugs(iam.GroupQuery{Persona: "channel", Page: iam.PageRequest{Limit: 3}}))
	require.Equal(t, []string{"acme", "announcements", "golang", "python", "rust"}, slugs(iam.GroupQuery{Page: iam.PageRequest{Limit: 1}}))
	require.Equal(t, []string{"golang"}, slugs(iam.GroupQuery{Persona: "channel", Search: "GO"}))
	_, err = e.ListGroups(ctx, iam.GroupQuery{Page: iam.PageRequest{Cursor: "garbage"}})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeInvalidRequest))
	_, err = e.ListGroups(ctx, iam.GroupQuery{Persona: "nope"})
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona)

	// Members and memberships.
	grantRole(t, e, golangRef, iam.UserSubject(carol), "moderator")
	grantRole(t, e, golangRef, iam.UserSubject(dave), "moderator")
	grantRole(t, e, golangRef, iam.UserSubject(erin), "janitor")
	members := func(q iam.MemberQuery) map[string]iam.Role {
		t.Helper()
		out := map[string]iam.Role{}
		for {
			page, err := e.ListGroupMembers(ctx, iam.GroupBySlug("channel", "golang"), q)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page.Items), q.Page.PageLimit())
			for _, m := range page.Items {
				require.Equal(t, iam.SubjectKindUser, m.Subject.Kind)
				out[m.Subject.ID] = m.Role
			}
			if page.Next == "" {
				return out
			}
			q.Page.Cursor = page.Next
		}
	}
	require.Equal(t, map[string]iam.Role{bob: iam.OwnerRole, carol: "moderator", dave: "moderator", erin: "janitor"}, members(iam.MemberQuery{Page: iam.PageRequest{Limit: 3}}))
	require.Equal(t, map[string]iam.Role{carol: "moderator", dave: "moderator"}, members(iam.MemberQuery{Roles: []iam.Role{"moderator"}, Page: iam.PageRequest{Limit: 1}}))
	require.Empty(t, members(iam.MemberQuery{Kinds: []iam.SubjectKind{iam.SubjectKindRemoteApplication}}))
	first, err := e.ListSubjectGroups(ctx, iam.UserSubject(admin), iam.PageRequest{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: announcements, Role: iam.OwnerRole}}, first.Items)
	second, err := e.ListSubjectGroups(ctx, iam.UserSubject(admin), iam.PageRequest{Cursor: first.Next, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: root, Role: "admin"}}, second.Items)
	require.Empty(t, second.Next)

	// Can is live for every actor kind.
	can := func(a iam.Actor, ref iam.GroupRef, p iam.Perm) bool {
		t.Helper()
		ok, err := e.Can(ctx, a, ref, p)
		require.NoError(t, err)
		return ok
	}
	annRef := iam.GroupByID(announcements.ID)
	require.True(t, can(iam.UserActor(carol), golangRef, "channel:posts:edit"))
	require.False(t, can(iam.UserActor(carol), annRef, "channel:posts:edit"), "a group role applies only in its group")
	require.True(t, can(iam.UserActor(admin), golangRef, "channel:posts:edit"), "a root role applies in every group")
	require.False(t, can(iam.UserActor(carol).Within("channel:members:read"), golangRef, "channel:posts:edit"), "a ceiling narrows")
	require.True(t, can(iam.APIKeyActor(key.ID), golangRef, "channel:posts:edit"))
	require.False(t, can(iam.APIKeyActor(key.ID), annRef, "channel:posts:edit"), "a key is bound to its group")
	local := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://groups.test", Subject: carol, Permissions: []iam.Perm{"channel:members:read"}})
	require.True(t, can(local, golangRef, "channel:members:read"))
	require.False(t, can(local, golangRef, "channel:posts:edit"), "a delegation is capped by its permissions")
	foreign := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://elsewhere.test", Subject: carol, Permissions: []iam.Perm{"channel:members:read"}})
	require.False(t, can(foreign, golangRef, "channel:members:read"), "a foreign delegation carries no authority here")
	require.True(t, can(iam.SystemActor(), golangRef, "channel:posts:edit"))
	require.False(t, can(iam.Actor{}, golangRef, "channel:posts:edit"))
	_, err = e.Can(ctx, iam.UserActor(carol), golangRef, "channel:posts:pin")
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	require.NoError(t, e.Ban(ctx, iam.SystemActor(), dave, iam.Ban{}))
	require.False(t, can(iam.UserActor(dave), golangRef, "channel:posts:edit"), "a banned user holds nothing")

	perms, err := e.EffectivePermissions(ctx, iam.UserActor(carol), []iam.GroupRef{golangRef, annRef, iam.GroupBySlug("channel", "missing")})
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.ElementsMatch(t, []iam.Perm{"channel:posts:edit", "channel:members:read"}, perms[golang.ID])
	perms, err = e.EffectivePermissions(ctx, iam.UserActor(admin).Within("channel:posts:edit", "channel:self:read"), []iam.GroupRef{golangRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{"channel:posts:edit", "channel:self:read"}, perms[golang.ID], "a ceiling narrows channel:* to what it permits")
	perms, err = e.EffectivePermissions(ctx, iam.APIKeyActor(key.ID), []iam.GroupRef{golangRef, annRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{"channel:posts:edit", "channel:members:read"}, perms[golang.ID])
	require.NotContains(t, perms, announcements.ID)

	// Update needs self:update; a rename passes the slug claim.
	_, err = e.UpdateGroup(ctx, iam.UserActor(carol), golangRef, iam.GroupUpdate{DisplayName: new("Mine")})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = e.UpdateGroup(ctx, iam.UserActor(bob), golangRef, iam.GroupUpdate{Slug: new("announcements")})
	require.ErrorIs(t, err, iam.ErrGroupSlugReserved)
	updated, err := e.UpdateGroup(ctx, iam.UserActor(bob), golangRef, iam.GroupUpdate{Slug: new("go"), DisplayName: new("Gophers")})
	require.NoError(t, err)
	require.Equal(t, "go", updated.Slug)
	require.Equal(t, "Gophers", updated.DisplayName)
	_, err = e.UpdateGroup(ctx, iam.SystemActor(), iam.RootGroup(), iam.GroupUpdate{DisplayName: new("Site")})
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona)

	// Delete is a soft delete gated by self:delete.
	_, err = e.DeleteGroup(ctx, iam.UserActor(carol), golangRef)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	deleted, err := e.DeleteGroup(ctx, iam.UserActor(erin), golangRef)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	_, err = e.Group(ctx, iam.GroupBySlug("channel", "go"))
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	retained, err := e.Group(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, deleted, retained)
	require.False(t, can(iam.UserActor(bob), golangRef, "channel:posts:edit"), "a deleted group grants nothing")
	require.Equal(t, []string{"announcements", "python", "rust"}, slugs(iam.GroupQuery{Persona: "channel"}))
	require.Equal(t, []string{"announcements", "go", "python", "rust"}, slugs(iam.GroupQuery{Persona: "channel", IncludeDeleted: true}))
	replay, err := e.DeleteGroup(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, replay.DeletedAt)
	_, err = e.DeleteGroup(ctx, iam.RootGroup())
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona)

	// Purge is the system's permanent delete.
	require.ErrorIs(t, e.PurgeGroup(ctx, iam.UserActor(bob), golangRef, iam.PurgeGroupOptions{}), iam.ErrInsufficientAuthority)
	require.NoError(t, e.PurgeGroup(ctx, golangRef, iam.PurgeGroupOptions{}))
	require.NoError(t, e.PurgeGroup(ctx, golangRef, iam.PurgeGroupOptions{}), "purging again is a no-op")
	_, err = e.Group(ctx, golangRef)
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
}

// H2, N9: adding a member by email never binds an account. Every address gets
// the same invitation; only the account that proved the address accepts it.
func TestAddMemberByEmailNeverBindsAnUnprovenAccount(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, instanceCreateTestConfig(), pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, token := newInstanceTestUser(t, srv, "h2owner")
	_, err = seedGroup(ctx, client, "org", "h2-acme", owner)
	require.NoError(t, err)
	add := func(email string) *httptest.ResponseRecorder {
		return serveAuthJSON(srv, http.MethodPost, "/org/h2-acme/members", `{"email":"`+email+`","role":"member"}`, token)
	}
	roleOf := func(userID string) iam.Role {
		roles, err := client.GroupRoles(ctx, iam.GroupBySlug("org", "h2-acme"), []iam.Subject{iam.UserSubject(userID)})
		require.NoError(t, err)
		return roles[iam.UserSubject(userID)]
	}

	squatter, err := client.createUser(ctx, "newhire@h2.test", "h2squatter")
	require.NoError(t, err)
	w := add("newhire@h2.test")
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"invited":true`)
	require.Empty(t, roleOf(squatter.ID), "an unverified email never receives a role")

	gone, err := client.createUser(ctx, "gone@h2.test", "h2gone")
	require.NoError(t, err)
	require.NoError(t, client.markEmailVerified(ctx, gone.ID))
	require.NoError(t, client.softDelete(ctx, gone.ID))
	w = add("gone@h2.test")
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Empty(t, roleOf(gone.ID), "a deleted account never receives a role")

	proven, provenToken := newInstanceTestUser(t, srv, "h2proven")
	provenUser, err := client.getUserByID(ctx, proven)
	require.NoError(t, err)
	w = add(strings.ToUpper(*provenUser.Email))
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Empty(t, roleOf(proven), "a verified address is invited, never added")
	var invited struct {
		Invite struct {
			Code string `json:"code"`
		} `json:"invite"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &invited))
	redeem := func(token string) *httptest.ResponseRecorder {
		return serveAuthJSON(srv, http.MethodPost, "/invites/redeem", `{"code":"`+invited.Invite.Code+`"}`, token)
	}
	_, strangerToken := newInstanceTestUser(t, srv, "h2stranger")
	require.Equal(t, http.StatusNotFound, redeem(strangerToken).Code, "only the invited address accepts")
	accepted := redeem(provenToken)
	require.Equal(t, http.StatusOK, accepted.Code, accepted.Body.String())
	require.Equal(t, iam.Role("member"), roleOf(proven))
}

// M2: redefining or deleting a held custom role changes what its holders
// have, so it needs the authority to manage those holders, and a name live
// rows still reference is never re-bound.
func TestCustomRoleChangesNeedHolderAuthority(t *testing.T) {
	e := groupsTestEngine(t, iam.TwoFactorDisabled, RoleConfig{
		Personas: map[string]Persona{"channel": {Permissions: []string{"channel:posts:read", "channel:posts:write"}, CustomRoles: true, APIKeys: true}},
		Roles: []Role{
			{Persona: "channel", Name: "designer", Permissions: []string{"channel:roles:manage", "channel:posts:*"}},
			{Persona: "channel", Name: "keeper", Permissions: []string{"channel:roles:manage", "channel:posts:*", "channel:members:manage"}},
		},
	})
	ctx := t.Context()
	owner, designer, keeper, holder := newGroupsUser(t, e, "m2owner"), newGroupsUser(t, e, "m2designer"), newGroupsUser(t, e, "m2keeper"), newGroupsUser(t, e, "m2holder")
	gid, err := seedGroup(ctx, e, "channel", "m2", owner)
	require.NoError(t, err)
	ref := iam.GroupByID(gid)
	grantRole(t, e, ref, iam.UserSubject(designer), "designer")
	grantRole(t, e, ref, iam.UserSubject(keeper), "keeper")
	define := func(actor string, perms ...string) error {
		return e.DefineGroupRole(ctx, iam.UserActor(actor), ref, iam.CustomRole{Name: "commenter", Permissions: perms})
	}
	holds := func(p iam.Perm) bool {
		ok, err := e.Can(ctx, iam.UserActor(holder), ref, p)
		require.NoError(t, err)
		return ok
	}

	require.NoError(t, define(designer, "channel:posts:read"), "an unheld role is the designer's to shape")
	require.NoError(t, define(designer, "channel:posts:read", "channel:posts:write"))
	require.NoError(t, define(designer, "channel:posts:read"))
	grantRole(t, e, ref, iam.UserSubject(holder), "commenter")
	require.ErrorIs(t, define(designer, "channel:posts:*"), iam.ErrInsufficientAuthority, "widening a held role needs members:manage")
	require.ErrorIs(t, define(designer), iam.ErrInsufficientAuthority, "narrowing a held role needs members:manage")
	require.ErrorIs(t, e.DeleteGroupRole(ctx, iam.UserActor(designer), ref, "commenter"), iam.ErrInsufficientAuthority)
	require.False(t, holds("channel:posts:write"))
	require.NoError(t, define(keeper, "channel:posts:read", "channel:posts:write"))
	require.True(t, holds("channel:posts:write"))

	_, _, err = e.MintAPIKey(ctx, iam.UserActor(owner), ref, iam.NewAPIKey{Name: "commenter-key", Role: "commenter"})
	require.NoError(t, err)
	require.ErrorIs(t, define(keeper, "channel:posts:read"), iam.ErrInsufficientAuthority, "a role an API key holds needs credentials:manage")
	require.NoError(t, define(owner, "channel:posts:read"))
	require.False(t, holds("channel:posts:write"))

	// A catalog role removed from config leaves rows naming it; defining a
	// custom role of that name would hand them its permissions.
	_, err = e.pg.Exec(ctx, `INSERT INTO group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'retired')`, gid, keeper)
	require.Error(t, err, "one role per subject per group")
	_, err = e.pg.Exec(ctx, `UPDATE group_user_roles SET role='retired' WHERE permission_group_id=$1::uuid AND user_id=$2::uuid`, gid, keeper)
	require.NoError(t, err)
	err = e.DefineGroupRole(ctx, iam.UserActor(owner), ref, iam.CustomRole{Name: "retired", Permissions: []string{"channel:posts:write"}})
	require.ErrorIs(t, err, iam.ErrCustomRoleIsCatalogRole)
	ok, err := e.Can(ctx, iam.UserActor(keeper), ref, "channel:posts:write")
	require.NoError(t, err)
	require.False(t, ok)
}

// M3 and invariant #4: MFA follows permissions. A role reaching a permission
// the persona marks RequireMFA needs MFA of its holder however it is built:
// a catalog role, an include, a root role, a custom clone or a redefinition.
// API keys cannot hold one.
func TestMFAFollowsPermissions(t *testing.T) {
	e := groupsTestEngine(t, iam.TwoFactorOptional, RoleConfig{
		Personas: map[string]Persona{"channel": {
			Permissions: []string{"channel:posts:edit", "channel:posts:delete"},
			RequireMFA:  []string{"channel:posts:delete"},
			CustomRoles: true, APIKeys: true,
		}},
		Roles: []Role{
			{Persona: "channel", Name: "editor", Permissions: []string{"channel:posts:edit"}},
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
			{Persona: "channel", Name: "senior", Includes: []iam.Role{"moderator"}},
			{Persona: iam.RootPersona, Name: "staff", Permissions: []string{"channel:*"}},
		},
	})
	ctx := t.Context()
	sch := e.groupSchemaOrDefault()
	for role, want := range map[iam.Role]bool{"editor": false, "moderator": true, "senior": true, iam.OwnerRole: true} {
		r, ok := sch.Role("channel", role)
		require.True(t, ok)
		require.Equal(t, want, r.RequiresMFA, role)
	}
	rootOwner, _ := sch.Role(iam.RootPersona, iam.OwnerRole)
	require.True(t, rootOwner.RequiresMFA, "root:members:manage always needs MFA")

	plain, secure, keeper := newGroupsUser(t, e, "m3plain"), newGroupsUser(t, e, "m3secure"), newGroupsUser(t, e, "m3keeper")
	for _, id := range []string{secure, keeper} {
		_, err := e.enableFactor(ctx, id, "email", nil, authflow.AllowAdditionalFactors)
		require.NoError(t, err)
	}
	gid, err := seedGroup(ctx, e, "channel", "m3", keeper)
	require.NoError(t, err)
	ref := iam.GroupByID(gid)
	_, err = seedGroup(ctx, e, "channel", "m3-unowned", plain)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired, "the owner role reaches the MFA permission")

	op := iam.SystemActor()
	require.ErrorIs(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "moderator"), iam.ErrTwoFAEnrollmentRequired)
	require.ErrorIs(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "senior"), iam.ErrTwoFAEnrollmentRequired, "an include carries MFA")
	require.ErrorIs(t, assignRole(ctx, e, op, iam.RootGroup(), iam.UserSubject(plain), "staff"), iam.ErrTwoFAEnrollmentRequired, "a root role covering the owner's permissions needs MFA")
	require.NoError(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "editor"))

	keeperActor := iam.UserActor(keeper)
	require.NoError(t, e.DefineGroupRole(ctx, keeperActor, ref, iam.CustomRole{Name: "clone", Permissions: []string{"channel:posts:delete"}}))
	require.ErrorIs(t, assignRole(ctx, e, keeperActor, ref, iam.UserSubject(plain), "clone"), iam.ErrTwoFAEnrollmentRequired, "a custom clone needs MFA")
	require.NoError(t, e.DefineGroupRole(ctx, keeperActor, ref, iam.CustomRole{Name: "helper", Permissions: []string{"channel:posts:edit"}}))
	require.NoError(t, assignRole(ctx, e, keeperActor, ref, iam.UserSubject(plain), "helper"))
	require.ErrorIs(t, e.DefineGroupRole(ctx, keeperActor, ref, iam.CustomRole{Name: "helper", Permissions: []string{"channel:posts:*"}}), iam.ErrTwoFAEnrollmentRequired, "a redefinition cannot hand MFA permissions to a holder without MFA")

	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "mod-key", Role: "moderator"})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "an API key cannot present MFA")
	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "editor-key", Role: "editor"})
	require.NoError(t, err)
	require.NoError(t, e.DefineGroupRole(ctx, keeperActor, ref, iam.CustomRole{Name: "bot", Permissions: []string{"channel:posts:edit"}}))
	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "bot-key", Role: "bot"})
	require.NoError(t, err)
	require.ErrorIs(t, e.DefineGroupRole(ctx, keeperActor, ref, iam.CustomRole{Name: "bot", Permissions: []string{"channel:posts:delete"}}), iam.ErrRoleNotAssignable)

	// With MFA the same roles are held; dropping MFA drops them.
	require.NoError(t, assignRole(ctx, e, op, iam.RootGroup(), iam.UserSubject(secure), "staff"))
	ok, err := e.Can(ctx, iam.UserActor(secure), ref, "channel:posts:delete")
	require.NoError(t, err)
	require.True(t, ok)
	_, err = e.Disable2FAWithRemovedRoles(ctx, secure)
	require.NoError(t, err)
	ok, err = e.Can(ctx, iam.UserActor(secure), ref, "channel:posts:delete")
	require.NoError(t, err)
	require.False(t, ok, "no subject without MFA keeps an MFA permission")
}

// RequirePermission authenticates the request itself and checks the group
// the route names, live: a removed role stops working on the next request.
func TestRequirePermissionGatesTheRequestGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, instanceCreateTestConfig(), pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, _ := newInstanceTestUser(t, srv, "gateowner")
	member, token := newInstanceTestUser(t, srv, "gatemember")
	for _, slug := range []string{"gate-acme", "gate-other"} {
		_, err := seedGroup(ctx, client, "org", slug, owner)
		require.NoError(t, err)
	}
	acme := iam.GroupBySlug("org", "gate-acme")
	grantRole(t, client, acme, iam.UserSubject(member), "member")

	r := gin.New()
	r.GET("/orgs/:org", authkitgin.RequirePermission(client, "org:catalog:read", func(c *gin.Context) iam.GroupRef {
		return iam.GroupBySlug("org", c.Param("org"))
	}), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/admin", authkitgin.RequirePermission(client, iam.PermRootUsersRead, nil), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	get := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	require.Equal(t, http.StatusUnauthorized, get("/orgs/gate-acme", ""))
	require.Equal(t, http.StatusNoContent, get("/orgs/gate-acme", token))
	require.Equal(t, http.StatusForbidden, get("/orgs/gate-other", token))
	require.Equal(t, http.StatusForbidden, get("/orgs/missing", token))
	require.Equal(t, http.StatusForbidden, get("/admin", token))
	revokeRole(t, client, acme, iam.UserSubject(member), "member")
	require.Equal(t, http.StatusForbidden, get("/orgs/gate-acme", token), "a removed role stops working at once")
	require.Panics(t, func() { authkitgin.RequirePermission(client, "org:catalog:write", nil) })
}

// DELETE /<persona>/{slug} soft-deletes a group for an actor holding
// <persona>:self:delete.
func TestDeleteGroupRoute(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, instanceCreateTestConfig(), pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, ownerToken := newInstanceTestUser(t, srv, "delowner")
	member, memberToken := newInstanceTestUser(t, srv, "delmember")
	gid, err := seedGroup(ctx, client, "org", "doomed", owner)
	require.NoError(t, err)
	grantRole(t, client, iam.GroupByID(gid), iam.UserSubject(member), "member")

	w := serveAuthJSON(srv, http.MethodDelete, "/org/doomed", "", memberToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodDelete, "/org/doomed", "", ownerToken)
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	g, err := client.Group(ctx, iam.GroupByID(gid))
	require.NoError(t, err)
	require.NotNil(t, g.DeletedAt)
	w = serveAuthJSON(srv, http.MethodGet, "/org/doomed", "", ownerToken)
	require.Equal(t, http.StatusForbidden, w.Code, "a deleted group no longer resolves")
}
