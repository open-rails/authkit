package engine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
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

// The group operations end to end: host create, read, list, delete and
// purge, members and memberships, and live checks for every actor kind.
func TestGroupOperationsWorkflow(t *testing.T) {
	e := groupsTestEngine(t, iam.TwoFactorDisabled, RoleConfig{
		Personas: map[string]Persona{
			"channel": {Permissions: []string{"channel:posts:edit", "channel:metadata:edit"}, APIKeys: true, CustomRoles: true},
			"org":     {Permissions: []string{"org:records:read"}},
		},
		Roles: []Role{
			{Persona: "root", Name: "admin", Permissions: []string{"channel:*"}},
			{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:edit", "channel:members:read"}},
			{Persona: "channel", Name: "editor", Permissions: []string{"channel:metadata:edit"}},
		},
	})
	ctx := t.Context()
	bob, carol, dave, erin, admin := newGroupsUser(t, e, "gbob"), newGroupsUser(t, e, "gcarol"), newGroupsUser(t, e, "gdave"), newGroupsUser(t, e, "gerin"), newGroupsUser(t, e, "gadmin")
	grantRole(t, e, iam.RootGroup(), iam.UserSubject(admin), "admin")
	owner := func(id string) *iam.Subject {
		s := iam.UserSubject(id)
		return &s
	}

	// The host creates a group of a declared persona, with an owner or none.
	golang, err := e.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("channel"), Owner: owner(bob)}, nil)
	require.NoError(t, err)
	require.Equal(t, ident.Persona("channel"), golang.Persona)
	require.False(t, golang.CreatedAt.IsZero())
	require.Nil(t, golang.DeletedAt)
	announcements, err := e.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("channel"), Owner: owner(admin)}, nil)
	require.NoError(t, err)
	acme, err := e.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("org")}, nil)
	require.NoError(t, err)
	for _, persona := range []iam.Persona{iam.RootPersona, ident.Persona("nope"), iam.Persona{}} {
		_, err := e.CreateGroup(ctx, iam.NewGroup{Persona: persona}, nil)
		require.ErrorIs(t, err, iam.ErrUnknownGroupPersona, persona)
	}
	_, err = e.CreateGroup(ctx, iam.NewGroup{Persona: ident.Persona("channel"), Owner: owner("not-a-uuid")}, nil)
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	rust, err := seedGroup(ctx, e, ident.Persona("channel"), "")
	require.NoError(t, err)
	python, err := seedGroup(ctx, e, ident.Persona("channel"), "")
	require.NoError(t, err)
	golangRef := iam.GroupByID(golang.ID)
	key, _, err := e.MintAPIKey(ctx, iam.UserActor(bob), golangRef, iam.NewAPIKey{Name: "bot", Role: mustRole("channel:moderator")})
	require.NoError(t, err)

	// Reads.
	got, err := e.Group(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, golang, got)
	root, err := e.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona, root.Persona)
	for _, ref := range []iam.GroupRef{iam.GroupByID("not-a-uuid"), iam.GroupByID(uuid.NewString()), {}} {
		_, err = e.Group(ctx, ref)
		require.ErrorIs(t, err, iam.ErrGroupNotFound)
	}
	batch, err := e.Groups(ctx, []string{golang.ID, acme.ID, uuid.NewString(), golang.ID})
	require.NoError(t, err)
	require.Equal(t, map[string]iam.Group{golang.ID: golang, acme.ID: acme}, batch)

	// Lists page oldest first, by id.
	ids := func(q iam.GroupQuery) []string {
		t.Helper()
		var out []string
		for {
			page, err := e.ListGroups(ctx, q)
			require.NoError(t, err)
			for _, g := range page.Items {
				out = append(out, g.ID)
			}
			if page.Next == "" {
				require.True(t, slices.IsSorted(out), "groups list oldest first")
				return out
			}
			q.Page.Cursor = page.Next
		}
	}
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: ident.Persona("channel"), Page: iam.PageRequest{Limit: 3}}))
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, acme.ID, rust, python}, ids(iam.GroupQuery{Page: iam.PageRequest{Limit: 1}}))
	_, err = e.ListGroups(ctx, iam.GroupQuery{Page: iam.PageRequest{Cursor: "garbage"}})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeInvalidRequest))
	_, err = e.ListGroups(ctx, iam.GroupQuery{Persona: ident.Persona("nope")})
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona)

	// Members and memberships.
	grantRole(t, e, golangRef, iam.UserSubject(carol), "moderator")
	grantRole(t, e, golangRef, iam.UserSubject(dave), "moderator")
	grantRole(t, e, golangRef, iam.UserSubject(erin), "editor")
	members := func(q iam.MemberQuery) map[string]iam.Role {
		t.Helper()
		out := map[string]iam.Role{}
		for {
			page, err := e.ListGroupMembers(ctx, golangRef, q)
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
	require.Equal(t, map[string]iam.Role{bob: mustRole("channel:owner"), carol: mustRole("channel:moderator"), dave: mustRole("channel:moderator"), erin: mustRole("channel:editor")}, members(iam.MemberQuery{Page: iam.PageRequest{Limit: 3}}))
	require.Equal(t, map[string]iam.Role{carol: mustRole("channel:moderator"), dave: mustRole("channel:moderator")}, members(iam.MemberQuery{Roles: []iam.Role{mustRole("channel:moderator")}, Page: iam.PageRequest{Limit: 1}}))
	require.Empty(t, members(iam.MemberQuery{Kinds: []iam.SubjectKind{iam.SubjectKindRemoteApplication}}))
	first, err := e.ListSubjectGroups(ctx, iam.UserSubject(admin), iam.PageRequest{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: announcements, Role: mustRole("channel:owner")}}, first.Items)
	second, err := e.ListSubjectGroups(ctx, iam.UserSubject(admin), iam.PageRequest{Cursor: first.Next, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: root, Role: mustRole("root:admin")}}, second.Items)
	require.Empty(t, second.Next)

	// Can is live for every actor kind.
	can := func(a iam.Actor, ref iam.GroupRef, p iam.Perm) bool {
		t.Helper()
		ok, err := e.Can(ctx, a, ref, p)
		require.NoError(t, err)
		return ok
	}
	annRef := iam.GroupByID(announcements.ID)
	require.True(t, can(iam.UserActor(carol), golangRef, ident.Perm("channel:posts:edit")))
	require.False(t, can(iam.UserActor(carol), annRef, ident.Perm("channel:posts:edit")), "a group role applies only in its group")
	require.True(t, can(iam.UserActor(admin), golangRef, ident.Perm("channel:posts:edit")), "a root role applies in every group")
	require.False(t, can(iam.UserActor(carol).Within(ident.Perm("channel:members:read")), golangRef, ident.Perm("channel:posts:edit")), "a ceiling narrows")
	require.True(t, can(iam.APIKeyActor(key.ID), golangRef, ident.Perm("channel:posts:edit")))
	require.False(t, can(iam.APIKeyActor(key.ID), annRef, ident.Perm("channel:posts:edit")), "a key is bound to its group")
	local := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://groups.test", Subject: carol, Permissions: []iam.Perm{ident.Perm("channel:members:read")}})
	require.True(t, can(local, golangRef, ident.Perm("channel:members:read")))
	require.False(t, can(local, golangRef, ident.Perm("channel:posts:edit")), "a delegation is capped by its permissions")
	foreign := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://elsewhere.test", Subject: carol, Permissions: []iam.Perm{ident.Perm("channel:members:read")}})
	require.False(t, can(foreign, golangRef, ident.Perm("channel:members:read")), "a foreign delegation carries no authority here")
	require.True(t, can(iam.SystemActor(), golangRef, ident.Perm("channel:posts:edit")))
	require.False(t, can(iam.Actor{}, golangRef, ident.Perm("channel:posts:edit")))
	_, err = e.Can(ctx, iam.UserActor(carol), golangRef, ident.Perm("channel:posts:pin"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	_, err = e.Can(ctx, iam.UserActor(carol), golangRef, ident.Perm("channel:self:delete"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission, "AuthKit registers no self permissions")
	require.True(t, can(iam.UserActor(erin), golangRef, ident.Perm("channel:metadata:edit")), "an app catalog may name any resource")
	require.NoError(t, e.Ban(ctx, iam.SystemActor(), dave, iam.Ban{}))
	require.False(t, can(iam.UserActor(dave), golangRef, ident.Perm("channel:posts:edit")), "a banned user holds nothing")

	perms, err := e.EffectivePermissions(ctx, iam.UserActor(carol), []iam.GroupRef{golangRef, annRef, iam.GroupByID(uuid.NewString())})
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.ElementsMatch(t, []iam.Perm{ident.Perm("channel:posts:edit"), ident.Perm("channel:members:read")}, perms[golang.ID])
	perms, err = e.EffectivePermissions(ctx, iam.UserActor(admin).Within(ident.Perm("channel:posts:edit"), ident.Perm("channel:metadata:edit")), []iam.GroupRef{golangRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{ident.Perm("channel:posts:edit"), ident.Perm("channel:metadata:edit")}, perms[golang.ID], "a ceiling narrows channel:* to what it permits")
	perms, err = e.EffectivePermissions(ctx, iam.APIKeyActor(key.ID), []iam.GroupRef{golangRef, annRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{ident.Perm("channel:posts:edit"), ident.Perm("channel:members:read")}, perms[golang.ID])
	require.NotContains(t, perms, announcements.ID)

	// Delete is the host's soft delete.
	require.NoError(t, e.DeleteGroup(ctx, golangRef, nil))
	deleted, err := e.Group(ctx, golangRef)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	require.False(t, can(iam.UserActor(bob), golangRef, ident.Perm("channel:posts:edit")), "a deleted group grants nothing")
	require.ElementsMatch(t, []string{announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: ident.Persona("channel")}))
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: ident.Persona("channel"), IncludeDeleted: true}))
	require.NoError(t, e.DeleteGroup(ctx, golangRef, nil))
	replay, err := e.Group(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, replay.DeletedAt, "deleting again keeps the first DeletedAt")
	require.ErrorIs(t, e.DeleteGroup(ctx, iam.RootGroup(), nil), iam.ErrUnknownGroupPersona)
	require.ErrorIs(t, e.DeleteGroup(ctx, iam.GroupByID(uuid.NewString()), nil), iam.ErrGroupNotFound)

	// Purge is the host's permanent delete.
	require.NoError(t, e.PurgeGroup(ctx, golangRef, nil))
	require.NoError(t, e.PurgeGroup(ctx, golangRef, nil), "purging again is a no-op")
	_, err = e.Group(ctx, golangRef)
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	require.ErrorIs(t, e.PurgeGroup(ctx, iam.RootGroup(), nil), iam.ErrUnknownGroupPersona)
}

// H2, N9: adding a member by email never binds an account. Every address gets
// the same invitation; only the account that proved the address accepts it.
func TestAddMemberByEmailNeverBindsAnUnprovenAccount(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, orgTestConfig(), pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, token := newInstanceTestUser(t, srv, "h2owner")
	gid, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	add := func(email string) *httptest.ResponseRecorder {
		return serveAuthJSON(srv, http.MethodPost, "/groups/"+gid+"/members", `{"email":"`+email+`","role":"member"}`, token)
	}
	roleOf := func(userID string) iam.Role {
		roles, err := client.GroupRoles(ctx, iam.GroupByID(gid), []iam.Subject{iam.UserSubject(userID)})
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
	require.Equal(t, mustRole("org:member"), roleOf(proven))
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
	gid, err := seedGroup(ctx, e, ident.Persona("channel"), owner)
	require.NoError(t, err)
	ref := iam.GroupByID(gid)
	grantRole(t, e, ref, iam.UserSubject(designer), "designer")
	grantRole(t, e, ref, iam.UserSubject(keeper), "keeper")
	define := func(actor string, perms ...string) error {
		return defineRole(e, ctx, iam.UserActor(actor), ref, "commenter", perms)
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
	require.ErrorIs(t, e.DeleteGroupRole(ctx, iam.UserActor(designer), ref, mustRole("channel:commenter")), iam.ErrInsufficientAuthority)
	require.False(t, holds(ident.Perm("channel:posts:write")))
	require.NoError(t, define(keeper, "channel:posts:read", "channel:posts:write"))
	require.True(t, holds(ident.Perm("channel:posts:write")))

	_, _, err = e.MintAPIKey(ctx, iam.UserActor(owner), ref, iam.NewAPIKey{Name: "commenter-key", Role: mustRole("channel:commenter")})
	require.NoError(t, err)
	require.ErrorIs(t, define(keeper, "channel:posts:read"), iam.ErrInsufficientAuthority, "a role an API key holds needs credentials:manage")
	require.NoError(t, define(owner, "channel:posts:read"))
	require.False(t, holds(ident.Perm("channel:posts:write")))

	// A catalog role removed from config leaves rows naming it; defining a
	// custom role of that name would hand them its permissions.
	_, err = e.pg.Exec(ctx, `INSERT INTO group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'retired')`, gid, keeper)
	require.Error(t, err, "one role per subject per group")
	_, err = e.pg.Exec(ctx, `UPDATE group_user_roles SET role='retired' WHERE permission_group_id=$1::uuid AND user_id=$2::uuid`, gid, keeper)
	require.NoError(t, err)
	err = defineRole(e, ctx, iam.UserActor(owner), ref, "retired", []string{"channel:posts:write"})
	require.ErrorIs(t, err, iam.ErrCustomRoleIsCatalogRole)
	ok, err := e.Can(ctx, iam.UserActor(keeper), ref, ident.Perm("channel:posts:write"))
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
			{Persona: "channel", Name: "senior", Includes: []string{"moderator"}},
			{Persona: "root", Name: "staff", Permissions: []string{"channel:*"}},
		},
	})
	ctx := t.Context()
	sch := e.groupSchemaOrDefault()
	for role, want := range map[string]bool{"editor": false, "moderator": true, "senior": true, "owner": true} {
		r, ok := sch.RoleNamed(ident.Persona("channel"), role)
		require.True(t, ok)
		require.Equal(t, want, r.RequiresMFA, role)
	}
	rootOwner, _ := sch.Role(iam.RootPersona, iam.RootPersona.OwnerRole())
	require.True(t, rootOwner.RequiresMFA, "root:members:manage always needs MFA")

	plain, secure, keeper := newGroupsUser(t, e, "m3plain"), newGroupsUser(t, e, "m3secure"), newGroupsUser(t, e, "m3keeper")
	for _, id := range []string{secure, keeper} {
		_, err := e.enableFactor(ctx, id, "email", nil, authflow.AllowAdditionalFactors)
		require.NoError(t, err)
	}
	gid, err := seedGroup(ctx, e, ident.Persona("channel"), keeper)
	require.NoError(t, err)
	ref := iam.GroupByID(gid)
	_, err = seedGroup(ctx, e, ident.Persona("channel"), plain)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired, "the owner role reaches the MFA permission")

	op := iam.SystemActor()
	require.ErrorIs(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "moderator"), iam.ErrTwoFAEnrollmentRequired)
	require.ErrorIs(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "senior"), iam.ErrTwoFAEnrollmentRequired, "an include carries MFA")
	require.ErrorIs(t, assignRole(ctx, e, op, iam.RootGroup(), iam.UserSubject(plain), "staff"), iam.ErrTwoFAEnrollmentRequired, "a root role covering the owner's permissions needs MFA")
	require.NoError(t, assignRole(ctx, e, op, ref, iam.UserSubject(plain), "editor"))

	keeperActor := iam.UserActor(keeper)
	require.NoError(t, defineRole(e, ctx, keeperActor, ref, "clone", []string{"channel:posts:delete"}))
	require.ErrorIs(t, assignRole(ctx, e, keeperActor, ref, iam.UserSubject(plain), "clone"), iam.ErrTwoFAEnrollmentRequired, "a custom clone needs MFA")
	require.NoError(t, defineRole(e, ctx, keeperActor, ref, "helper", []string{"channel:posts:edit"}))
	require.NoError(t, assignRole(ctx, e, keeperActor, ref, iam.UserSubject(plain), "helper"))
	require.ErrorIs(t, defineRole(e, ctx, keeperActor, ref, "helper", []string{"channel:posts:*"}), iam.ErrTwoFAEnrollmentRequired, "a redefinition cannot hand MFA permissions to a holder without MFA")

	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "mod-key", Role: mustRole("channel:moderator")})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "an API key cannot present MFA")
	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "editor-key", Role: mustRole("channel:editor")})
	require.NoError(t, err)
	require.NoError(t, defineRole(e, ctx, keeperActor, ref, "bot", []string{"channel:posts:edit"}))
	_, _, err = e.MintAPIKey(ctx, iam.UserActor(keeper), ref, iam.NewAPIKey{Name: "bot-key", Role: mustRole("channel:bot")})
	require.NoError(t, err)
	require.ErrorIs(t, defineRole(e, ctx, keeperActor, ref, "bot", []string{"channel:posts:delete"}), iam.ErrRoleNotAssignable)

	// With MFA the same roles are held; dropping MFA drops them.
	require.NoError(t, assignRole(ctx, e, op, iam.RootGroup(), iam.UserSubject(secure), "staff"))
	ok, err := e.Can(ctx, iam.UserActor(secure), ref, ident.Perm("channel:posts:delete"))
	require.NoError(t, err)
	require.True(t, ok)
	_, err = e.Disable2FAWithRemovedRoles(ctx, secure)
	require.NoError(t, err)
	ok, err = e.Can(ctx, iam.UserActor(secure), ref, ident.Perm("channel:posts:delete"))
	require.NoError(t, err)
	require.False(t, ok, "no subject without MFA keeps an MFA permission")
}

// RequirePermission authenticates the request itself and checks the group
// the route names, live: a removed role stops working on the next request.
func TestRequirePermissionGatesTheRequestGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pg := testdb.ScratchPostgres(t)
	client := newServerClient(t, orgTestConfig(), pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, _ := newInstanceTestUser(t, srv, "gateowner")
	member, token := newInstanceTestUser(t, srv, "gatemember")
	acmeID, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	otherID, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	acme := iam.GroupByID(acmeID)
	grantRole(t, client, acme, iam.UserSubject(member), "member")

	r := gin.New()
	org := r.Group("/orgs/:org", func(c *gin.Context) { authkitgin.SetGroup(c, iam.GroupByID(c.Param("org"))) })
	org.GET("", authkitgin.RequirePermission(client, ident.Perm("org:catalog:read")), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/unloaded/:org", authkitgin.RequirePermission(client, ident.Perm("org:catalog:read")), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/admin", authkitgin.RequirePermissionOn(client, iam.RootGroup(), iam.PermRootUsersRead), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	get := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	require.Equal(t, http.StatusUnauthorized, get("/orgs/"+acmeID, ""))
	require.Equal(t, http.StatusNoContent, get("/orgs/"+acmeID, token))
	require.Equal(t, http.StatusForbidden, get("/orgs/"+otherID, token))
	require.Equal(t, http.StatusForbidden, get("/orgs/"+uuid.NewString(), token))
	require.Equal(t, http.StatusForbidden, get("/admin", token))
	require.Equal(t, http.StatusInternalServerError, get("/unloaded/"+acmeID, token), "no group attached fails closed, never falls back to root")
	revokeRole(t, client, acme, iam.UserSubject(member), "member")
	require.Equal(t, http.StatusForbidden, get("/orgs/"+acmeID, token), "a removed role stops working at once")
	require.Panics(t, func() { authkitgin.RequirePermission(client, ident.Perm("org:catalog:write")) })
}

// Groups have no route of their own: no request creates, reads, renames or
// deletes one, and old slug-addressed routes are gone. A route of a
// capability the group's persona lacks is refused like an unknown group.
func TestGroupRoutesAddressGroupsByID(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := orgTestConfig()
	cfg.Roles.Personas["team"] = Persona{Permissions: []string{"team:docs:read"}}
	client := newServerClient(t, cfg, pg.Pool)
	srv, err := newTestService(client, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	ctx := t.Context()
	owner, ownerToken := newInstanceTestUser(t, srv, "idowner")
	member, memberToken := newInstanceTestUser(t, srv, "idmember")
	gid, err := seedGroup(ctx, client, ident.Persona("org"), owner)
	require.NoError(t, err)
	team, err := seedGroup(ctx, client, ident.Persona("team"), owner)
	require.NoError(t, err)
	grantRole(t, client, iam.GroupByID(gid), iam.UserSubject(member), "member")

	w := serveAuthJSON(srv, http.MethodGet, "/groups/"+gid+"/members", "", ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var list struct {
		GroupID string `json:"group_id"`
		Persona string `json:"persona"`
		Data    []struct {
			SubjectID string `json:"subject_id"`
			Role      string `json:"role"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Equal(t, gid, list.GroupID)
	require.Equal(t, "org", list.Persona)
	require.Len(t, list.Data, 2)
	require.Equal(t, http.StatusForbidden, serveAuthJSON(srv, http.MethodGet, "/groups/"+gid+"/members", "", memberToken).Code, "member lacks org:members:read")
	require.Equal(t, http.StatusForbidden, serveAuthJSON(srv, http.MethodGet, "/groups/"+uuid.NewString()+"/members", "", ownerToken).Code, "an unknown group is refused, not revealed")
	require.Equal(t, http.StatusForbidden, serveAuthJSON(srv, http.MethodGet, "/groups/"+team+"/remote-applications", "", ownerToken).Code, "team has no applications")
	require.Equal(t, http.StatusOK, serveAuthJSON(srv, http.MethodGet, "/groups/"+gid+"/remote-applications", "", ownerToken).Code)

	w = serveAuthJSON(srv, http.MethodPut, "/groups/"+gid+"/members/"+member+"/roles/member", "", ownerToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/me/permissions?group_id="+gid, "", memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, `{"object":"permission_set","group_id":"`+gid+`","permissions":["org:catalog:read"]}`, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/me/groups", "", memberToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"group_id":"`+gid+`"`)
	require.NotContains(t, w.Body.String(), "instance_slug")

	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/org"},
		{http.MethodGet, "/groups/" + gid},
		{http.MethodPatch, "/groups/" + gid},
		{http.MethodDelete, "/groups/" + gid},
		{http.MethodGet, "/org/" + gid + "/members"},
	} {
		w := serveAuthJSON(srv, req.method, req.path, `{"slug":"x"}`, ownerToken)
		require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, w.Code, "%s %s: %s", req.method, req.path, w.Body.String())
	}

	require.NoError(t, client.DeleteGroup(ctx, iam.GroupByID(gid), nil))
	require.Equal(t, http.StatusForbidden, serveAuthJSON(srv, http.MethodGet, "/groups/"+gid+"/members", "", ownerToken).Code, "a deleted group no longer resolves")
}
