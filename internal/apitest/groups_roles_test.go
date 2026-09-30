package apitest_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	hostauth "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
	"github.com/open-rails/authkit/verify"
)

// createGroup creates a group of persona owned by the user ownerID ("" = no
// owner), as the host does.
func createGroup(auth *authkit.Client, persona iam.Persona, ownerID string) (iam.Group, error) {
	g := iam.NewGroup{Persona: persona}
	if ownerID != "" {
		owner := iam.UserSubject(ownerID)
		g.Owner = &owner
	}
	return auth.CreateGroup(context.Background(), g)
}

func newGroup(t testing.TB, auth *authkit.Client, persona iam.Persona, ownerID string) iam.GroupRef {
	t.Helper()
	g, err := createGroup(auth, persona, ownerID)
	require.NoError(t, err)
	return iam.GroupByID(g.ID)
}

// orgModel is the permission model most tests here run: an org persona whose
// groups control remote applications, its member role, and a root site-admin
// who reads accounts. Tests declare more roles on it before authtest.New.
type orgModel struct {
	rbac      *authkit.Roles
	org       *authkit.PersonaDef
	catalog   iam.Perm // org:catalog:read
	member    iam.Role
	siteAdmin iam.Role
}

func newOrgModel(root ...authkit.PersonaOption) orgModel {
	rbac := authkit.NewRoles(root...)
	org := rbac.Persona("org", authkit.RemoteApplications)
	catalog := org.Permission("catalog", "read")
	return orgModel{rbac: rbac, org: org, catalog: catalog, member: org.Role("member", catalog),
		siteAdmin: rbac.Root.Role("site-admin", rbac.Root.Users.Read)}
}

func (m orgModel) config(c *authkit.Config) { c.Roles = m.rbac }

// The group operations end to end: host create, read, list, delete and
// purge, members and memberships, and live checks for every actor kind.
func TestGroupOperationsWorkflow(t *testing.T) {
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel", authkit.APIKeys)
	postsEdit := channel.Permission("posts", "edit")
	metadataEdit := channel.Permission("metadata", "edit")
	membersRead := channel.Members.Read
	org := rbac.Persona("org")
	org.Permission("records", "read")
	adminRole := rbac.Root.Role("admin", channel.All())
	moderator := channel.Role("moderator", postsEdit, membersRead)
	editor := channel.Role("editor", metadataEdit)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	ctx := t.Context()
	bob, carol, dave := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	erin, admin := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(admin.ID), adminRole)
	owner := func(id string) *iam.Subject {
		s := iam.UserSubject(id)
		return &s
	}

	// The host creates a group of a declared persona, with an owner or none.
	golang, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: channel.Persona, Owner: owner(bob.ID)})
	require.NoError(t, err)
	require.Equal(t, channel.Persona, golang.Persona)
	require.False(t, golang.CreatedAt.IsZero())
	require.Nil(t, golang.DeletedAt)
	announcements, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: channel.Persona, Owner: owner(admin.ID)})
	require.NoError(t, err)
	acme, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: org.Persona})
	require.NoError(t, err)
	for _, persona := range []iam.Persona{iam.RootPersona, wire[iam.Persona](t, "nope"), {}} {
		_, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
		require.ErrorIs(t, err, iam.ErrUnknownGroupPersona, persona)
	}
	_, err = auth.CreateGroup(ctx, iam.NewGroup{Persona: channel.Persona, Owner: owner("not-a-uuid")})
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	rust, python := newGroup(t, auth, channel.Persona, "").ID(), newGroup(t, auth, channel.Persona, "").ID()
	golangRef := iam.GroupByID(golang.ID)
	key, _, err := auth.MintAPIKey(ctx, iam.UserActor(bob.ID), golangRef, iam.NewAPIKey{Name: "bot", Role: moderator})
	require.NoError(t, err)

	// Reads.
	got, err := auth.Group(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, golang, got)
	root, err := auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona, root.Persona)
	for _, ref := range []iam.GroupRef{iam.GroupByID("not-a-uuid"), iam.GroupByID(uuid.NewString()), {}} {
		_, err = auth.Group(ctx, ref)
		require.ErrorIs(t, err, iam.ErrGroupNotFound)
	}
	batch, err := auth.Groups(ctx, []string{golang.ID, acme.ID, uuid.NewString(), golang.ID})
	require.NoError(t, err)
	require.Equal(t, map[string]iam.Group{golang.ID: golang, acme.ID: acme}, batch)

	// Lists page oldest first, by id.
	ids := func(q iam.GroupQuery) []string {
		t.Helper()
		var out []string
		for {
			page, err := auth.ListGroups(ctx, q)
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
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: channel.Persona, Page: iam.PageRequest{Limit: 3}}))
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, acme.ID, rust, python}, ids(iam.GroupQuery{Page: iam.PageRequest{Limit: 1}}))
	_, err = auth.ListGroups(ctx, iam.GroupQuery{Page: iam.PageRequest{Cursor: "garbage"}})
	requireIAMCode(t, err, "invalid_request")
	_, err = auth.ListGroups(ctx, iam.GroupQuery{Persona: wire[iam.Persona](t, "nope")})
	require.ErrorIs(t, err, iam.ErrUnknownGroupPersona)

	// Members and memberships.
	authtest.GrantRole(t, auth, golangRef, iam.UserSubject(carol.ID), moderator)
	authtest.GrantRole(t, auth, golangRef, iam.UserSubject(dave.ID), moderator)
	authtest.GrantRole(t, auth, golangRef, iam.UserSubject(erin.ID), editor)
	members := func(q iam.MemberQuery) map[string]iam.Role {
		t.Helper()
		out := map[string]iam.Role{}
		for {
			page, err := auth.ListGroupMembers(ctx, golangRef, q)
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
	require.Equal(t, map[string]iam.Role{bob.ID: channel.Owner, carol.ID: moderator, dave.ID: moderator, erin.ID: editor}, members(iam.MemberQuery{Page: iam.PageRequest{Limit: 3}}))
	require.Equal(t, map[string]iam.Role{carol.ID: moderator, dave.ID: moderator}, members(iam.MemberQuery{Roles: []iam.Role{moderator}, Page: iam.PageRequest{Limit: 1}}))
	require.Empty(t, members(iam.MemberQuery{Kinds: []iam.SubjectKind{iam.SubjectKindRemoteApplication}}))
	first, err := auth.ListSubjectGroups(ctx, iam.UserSubject(admin.ID), iam.PageRequest{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: announcements, Role: channel.Owner}}, first.Items)
	second, err := auth.ListSubjectGroups(ctx, iam.UserSubject(admin.ID), iam.PageRequest{Cursor: first.Next, Limit: 1})
	require.NoError(t, err)
	require.Equal(t, []iam.Membership{{Group: root, Role: adminRole}}, second.Items)
	require.Empty(t, second.Next)

	// Can is live for every actor kind.
	can := func(a iam.Actor, ref iam.GroupRef, p iam.Perm) bool {
		t.Helper()
		ok, err := auth.Can(ctx, a, ref, p)
		require.NoError(t, err)
		return ok
	}
	annRef := iam.GroupByID(announcements.ID)
	require.True(t, can(iam.UserActor(carol.ID), golangRef, postsEdit))
	require.False(t, can(iam.UserActor(carol.ID), annRef, postsEdit), "a group role applies only in its group")
	require.True(t, can(iam.UserActor(admin.ID), golangRef, postsEdit), "a root role applies in every group")
	require.False(t, can(iam.UserActor(carol.ID).Within(membersRead), golangRef, postsEdit), "a ceiling narrows")
	require.True(t, can(iam.APIKeyActor(key.ID), golangRef, postsEdit))
	require.False(t, can(iam.APIKeyActor(key.ID), annRef, postsEdit), "a key is bound to its group")
	local := iam.DelegatedActor(iam.DelegatedGrant{Issuer: authtest.Issuer, Subject: carol.ID, Permissions: []iam.Perm{membersRead}})
	require.True(t, can(local, golangRef, membersRead))
	require.False(t, can(local, golangRef, postsEdit), "a delegation is capped by its permissions")
	foreign := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://elsewhere.test", Subject: carol.ID, Permissions: []iam.Perm{membersRead}})
	require.False(t, can(foreign, golangRef, membersRead), "a foreign delegation carries no authority here")
	require.True(t, can(iam.SystemActor(), golangRef, postsEdit))
	require.False(t, can(iam.Actor{}, golangRef, postsEdit))
	_, err = auth.Can(ctx, iam.UserActor(carol.ID), golangRef, wire[iam.Perm](t, "channel:posts:pin"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission)
	_, err = auth.Can(ctx, iam.UserActor(carol.ID), golangRef, wire[iam.Perm](t, "channel:self:delete"))
	require.ErrorIs(t, err, iam.ErrUnknownPermission, "AuthKit registers no self permissions")
	require.True(t, can(iam.UserActor(erin.ID), golangRef, metadataEdit), "an app catalog may name any resource")
	require.NoError(t, auth.Ban(ctx, iam.SystemActor(), dave.ID, iam.Ban{}))
	require.False(t, can(iam.UserActor(dave.ID), golangRef, postsEdit), "a banned user holds nothing")

	perms, err := auth.EffectivePermissions(ctx, iam.UserActor(carol.ID), []iam.GroupRef{golangRef, annRef, iam.GroupByID(uuid.NewString())})
	require.NoError(t, err)
	require.Len(t, perms, 1)
	require.ElementsMatch(t, []iam.Perm{postsEdit, membersRead}, perms[golang.ID])
	perms, err = auth.EffectivePermissions(ctx, iam.UserActor(admin.ID).Within(postsEdit, metadataEdit), []iam.GroupRef{golangRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{postsEdit, metadataEdit}, perms[golang.ID], "a ceiling narrows channel:* to what it permits")
	perms, err = auth.EffectivePermissions(ctx, iam.APIKeyActor(key.ID), []iam.GroupRef{golangRef, annRef})
	require.NoError(t, err)
	require.ElementsMatch(t, []iam.Perm{postsEdit, membersRead}, perms[golang.ID])
	require.NotContains(t, perms, announcements.ID)

	// Delete is the host's soft delete.
	require.NoError(t, auth.DeleteGroup(ctx, golangRef))
	deleted, err := auth.Group(ctx, golangRef)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	require.False(t, can(iam.UserActor(bob.ID), golangRef, postsEdit), "a deleted group grants nothing")
	require.ElementsMatch(t, []string{announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: channel.Persona}))
	require.ElementsMatch(t, []string{golang.ID, announcements.ID, rust, python}, ids(iam.GroupQuery{Persona: channel.Persona, IncludeDeleted: true}))
	require.NoError(t, auth.DeleteGroup(ctx, golangRef))
	replay, err := auth.Group(ctx, golangRef)
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, replay.DeletedAt, "deleting again keeps the first DeletedAt")
	require.ErrorIs(t, auth.DeleteGroup(ctx, iam.RootGroup()), iam.ErrUnknownGroupPersona)
	require.ErrorIs(t, auth.DeleteGroup(ctx, iam.GroupByID(uuid.NewString())), iam.ErrGroupNotFound)

	// Purge is the host's permanent delete.
	require.NoError(t, auth.PurgeGroup(ctx, golangRef))
	require.NoError(t, auth.PurgeGroup(ctx, golangRef), "purging again is a no-op")
	_, err = auth.Group(ctx, golangRef)
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	require.ErrorIs(t, auth.PurgeGroup(ctx, iam.RootGroup()), iam.ErrUnknownGroupPersona)
}

// M3 and invariant #4: MFA follows permissions. A role reaching a permission
// the persona marks RequireMFA needs MFA of its holder however it is built (a
// catalog role, an include or a root role) and however it is granted (the Go
// API or the HTTP route). API keys cannot hold one.
func TestMFAFollowsPermissions(t *testing.T) {
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel", authkit.APIKeys)
	postsEdit := channel.Permission("posts", "edit")
	postsDelete := channel.Permission("posts", "delete")
	channel.RequireMFA(postsDelete)
	editor := channel.Role("editor", postsEdit)
	moderator := channel.Role("moderator", channel.Resource("posts").All())
	senior := channel.Role("senior", moderator)
	staff := rbac.Root.Role("staff", channel.All())
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorOptional
	}))
	ctx := t.Context()

	plain, secure, keeper := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	secure.TOTP = authtest.EnrollTOTP(t, auth, secure)
	keeper.TOTP = authtest.EnrollTOTP(t, auth, keeper)
	ref := newGroup(t, auth, channel.Persona, keeper.ID)
	_, err := createGroup(auth, channel.Persona, plain.ID)
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired, "the owner role reaches the MFA permission")

	op := iam.SystemActor()
	require.ErrorIs(t, assign(auth, op, ref, iam.UserSubject(plain.ID), moderator), iam.ErrTwoFAEnrollmentRequired)
	require.ErrorIs(t, assign(auth, op, ref, iam.UserSubject(plain.ID), senior), iam.ErrTwoFAEnrollmentRequired, "an include carries MFA")
	require.ErrorIs(t, assign(auth, op, iam.RootGroup(), iam.UserSubject(plain.ID), staff), iam.ErrTwoFAEnrollmentRequired, "a root role covering the owner's permissions needs MFA")
	require.NoError(t, assign(auth, op, ref, iam.UserSubject(plain.ID), editor))

	_, _, err = auth.MintAPIKey(ctx, iam.UserActor(keeper.ID), ref, iam.NewAPIKey{Name: "mod-key", Role: moderator})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "an API key cannot present MFA")
	_, _, err = auth.MintAPIKey(ctx, iam.UserActor(keeper.ID), ref, iam.NewAPIKey{Name: "editor-key", Role: editor})
	require.NoError(t, err)

	// With MFA the same roles are held; dropping MFA drops them.
	require.NoError(t, assign(auth, op, iam.RootGroup(), iam.UserSubject(secure.ID), staff))
	ok, err := auth.Can(ctx, iam.UserActor(secure.ID), ref, postsDelete)
	require.NoError(t, err)
	require.True(t, ok)
	res := newAPI(t, auth).do(request{method: http.MethodDelete, path: "/user/2fa", token: authtest.SignIn(t, auth, secure).AccessToken})
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.Contains(t, res.String(), `"role":"staff"`)
	ok, err = auth.Can(ctx, iam.UserActor(secure.ID), ref, postsDelete)
	require.NoError(t, err)
	require.False(t, ok, "no subject without MFA keeps an MFA permission")

	t.Run("the HTTP assignment gate", func(t *testing.T) {
		a := newAPI(t, auth)
		token := authtest.SignIn(t, auth, keeper).AccessToken
		subject := authtest.NewUser(t, auth)
		path := "/groups/" + ref.ID() + "/members/" + subject.ID + "/roles/moderator"
		res := a.do(request{method: http.MethodPut, path: path, token: token})
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		require.Equal(t, "2fa_enrollment_required", res.code())
		authtest.EnrollTOTP(t, auth, subject)
		res = a.do(request{method: http.MethodPut, path: path, token: token})
		require.Equal(t, http.StatusOK, res.status, "the same assignment once enrolled: %s", res)

		plain.TOTP = authtest.EnrollTOTP(t, auth, plain)
		_, err := createGroup(auth, channel.Persona, plain.ID)
		require.NoError(t, err, "the same owner once enrolled")
	})
}

// RequirePermission authenticates the request itself and checks the group
// the route names, live: a removed role stops working on the next request.
func TestRequirePermissionGatesTheRequestGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	owner, member := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, member).AccessToken
	acme := newGroup(t, auth, m.org.Persona, owner.ID)
	other := newGroup(t, auth, m.org.Persona, owner.ID)
	authtest.GrantRole(t, auth, acme, iam.UserSubject(member.ID), m.member)

	r := gin.New()
	org := r.Group("/orgs/:org", func(c *gin.Context) { authkitgin.SetGroup(c, iam.GroupByID(c.Param("org"))) })
	org.GET("", authkitgin.RequirePermission(auth, m.catalog), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/unloaded/:org", authkitgin.RequirePermission(auth, m.catalog), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.GET("/admin", authkitgin.RequirePermissionOn(auth, iam.RootGroup(), iam.PermRootUsersRead), func(c *gin.Context) { c.Status(http.StatusNoContent) })
	get := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	require.Equal(t, http.StatusUnauthorized, get("/orgs/"+acme.ID(), ""))
	require.Equal(t, http.StatusNoContent, get("/orgs/"+acme.ID(), token))
	require.Equal(t, http.StatusForbidden, get("/orgs/"+other.ID(), token))
	require.Equal(t, http.StatusForbidden, get("/orgs/"+uuid.NewString(), token))
	require.Equal(t, http.StatusForbidden, get("/admin", token))
	require.Equal(t, http.StatusInternalServerError, get("/unloaded/"+acme.ID(), token), "no group attached fails closed, never falls back to root")
	authtest.RevokeRole(t, auth, acme, iam.UserSubject(member.ID), m.member)
	require.Equal(t, http.StatusForbidden, get("/orgs/"+acme.ID(), token), "a removed role stops working at once")
	require.Panics(t, func() { authkitgin.RequirePermission(auth, wire[iam.Perm](t, "org:catalog:write")) })
}

// A group's routes address it by ID. An unknown or deleted group is refused
// like one the caller may not see.
func TestGroupRoutesAddressGroupsByID(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	a := newAPI(t, auth)
	owner, member := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	ownerToken, memberToken := authtest.SignIn(t, auth, owner).AccessToken, authtest.SignIn(t, auth, member).AccessToken
	group := newGroup(t, auth, m.org.Persona, owner.ID)
	gid := group.ID()
	authtest.GrantRole(t, auth, group, iam.UserSubject(member.ID), m.member)

	res := a.get("/groups/"+gid+"/members", ownerToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var list struct {
		GroupID string `json:"group_id"`
		Persona string `json:"persona"`
		Data    []struct {
			SubjectID string `json:"subject_id"`
			Role      string `json:"role"`
		} `json:"data"`
	}
	res.decode(t, &list)
	require.Equal(t, gid, list.GroupID)
	require.Equal(t, "org", list.Persona)
	require.Len(t, list.Data, 2)
	res = a.get("/groups/"+gid+"/members", memberToken)
	require.Equal(t, http.StatusForbidden, res.status, "member lacks org:members:read: %s", res)
	res = a.get("/groups/"+uuid.NewString()+"/members", ownerToken)
	require.Equal(t, http.StatusForbidden, res.status, "an unknown group is refused, not revealed: %s", res)

	res = a.do(request{method: http.MethodPut, path: "/groups/" + gid + "/members/" + member.ID + "/roles/member", token: ownerToken})
	require.Equal(t, http.StatusOK, res.status, res.String())
	res = a.get("/me/permissions?group_id="+gid, memberToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.JSONEq(t, `{"group_id":"`+gid+`","permissions":["org:catalog:read"]}`, res.String())
	res = a.get("/me/groups", memberToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.Contains(t, res.String(), `"group_id":"`+gid+`"`)
	require.NotContains(t, res.String(), "instance_slug")

	require.NoError(t, auth.DeleteGroup(t.Context(), group))
	res = a.get("/groups/"+gid+"/members", ownerToken)
	require.Equal(t, http.StatusForbidden, res.status, "a deleted group no longer resolves: %s", res)
}

// Role operations. The system skips authority rules, never invariants. Any
// other actor, of every kind (a user, its API key, an application, a
// delegation), grants only what it covers, strips no role above its own, and
// has no authority in another group or beyond its ceiling.
func TestGroupRoleOperations(t *testing.T) {
	rbac := authkit.NewRoles()
	postsEdit := rbac.Root.Permission("posts", "edit")
	editor := rbac.Root.Role("editor", postsEdit)
	admin := rbac.Root.Role("admin", rbac.Root.Members.Manage, postsEdit)
	org := rbac.Persona("org", authkit.APIKeys, authkit.RemoteApplications)
	catalog := org.Permission("catalog", "read")
	member := org.Role("member", catalog)
	manager := org.Role("manager", org.Members.Manage, org.Credentials.Manage, catalog)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	ctx := t.Context()
	newSubject := func(t *testing.T) iam.Subject { return iam.UserSubject(authtest.NewUser(t, auth).ID) }

	t.Run("root", func(t *testing.T) {
		root, stranger := iam.RootGroup(), iam.UserSubject(uuid.NewString())
		owner, adminUser, editorUser, other := newSubject(t), newSubject(t), newSubject(t), newSubject(t)

		// The system skips authority rules, never invariants.
		authtest.GrantRole(t, auth, root, owner, rbac.Root.Owner)
		require.ErrorIs(t, unassign(auth, iam.SystemActor(), root, owner, rbac.Root.Owner), iam.ErrLastOwner)
		require.ErrorIs(t, assign(auth, iam.SystemActor(), root, owner, editor), iam.ErrLastOwner)
		require.ErrorIs(t, assign(auth, iam.SystemActor(), root, stranger, editor), iam.ErrUserNotFound)
		_, err := auth.AssignGroupRoles(ctx, iam.SystemActor(), root, []iam.Subject{editorUser}, wire[iam.Role](t, "root:unknown"))
		require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
		_, err = auth.AssignGroupRoles(ctx, iam.Actor{}, root, []iam.Subject{editorUser}, editor)
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "the zero actor is refused")

		// root:members:manage lets a bounded admin grant what it covers, never more.
		authtest.GrantRole(t, auth, root, adminUser, admin)
		res, err := auth.AssignGroupRoles(ctx, iam.UserActor(adminUser.ID), root, []iam.Subject{editorUser, other, stranger}, editor)
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		require.NoError(t, res[1].Err)
		require.ErrorIs(t, res[2].Err, iam.ErrUserNotFound, "items fail independently")
		require.ErrorIs(t, assign(auth, iam.UserActor(adminUser.ID), root, other, rbac.Root.Owner), iam.ErrRoleAssignmentEscalation)
		require.ErrorIs(t, removeMember(auth, iam.UserActor(adminUser.ID), root, owner), iam.ErrRoleAssignmentEscalation)
		require.ErrorIs(t, unassign(auth, iam.UserActor(editorUser.ID), root, other, editor), iam.ErrInsufficientAuthority)
		require.ErrorIs(t, assign(auth, iam.UserActor(owner.ID).Within(rbac.Root.Resource("posts").All()), root, other, admin), iam.ErrInsufficientAuthority, "a ceiling narrows even the owner")

		held, err := auth.GroupRoles(ctx, root, []iam.Subject{owner, adminUser, editorUser, other, stranger})
		require.NoError(t, err)
		require.Equal(t, map[iam.Subject]iam.Role{owner: rbac.Root.Owner, adminUser: admin, editorUser: editor, other: editor}, held)

		res, err = auth.RemoveGroupMembers(ctx, iam.UserActor(adminUser.ID), root, []iam.Subject{editorUser, stranger})
		require.NoError(t, err)
		require.NoError(t, res[0].Err)
		require.NoError(t, res[1].Err, "removing a non-member is a no-op")
		require.NoError(t, unassign(auth, iam.UserActor(adminUser.ID), root, other, admin), "unassigning a role not held is a no-op")

		// A banned actor is not live, whatever roles it still holds.
		require.NoError(t, auth.Ban(ctx, iam.SystemActor(), adminUser.ID, iam.Ban{}))
		_, err = auth.AssignGroupRoles(ctx, iam.UserActor(adminUser.ID), root, []iam.Subject{editorUser}, editor)
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})

	// Every actor below holds the bounded manager role in acme; founder owns
	// acme and other.
	founder, mgr := newSubject(t), newSubject(t)
	acme := newGroup(t, auth, org.Persona, founder.ID)
	other := newGroup(t, auth, org.Persona, founder.ID)
	authtest.GrantRole(t, auth, acme, mgr, manager)
	app, err := auth.UpsertRemoteApplication(ctx, iam.SystemActor(), acme, iam.RemoteApplication{Slug: "acme-app", Issuer: "https://acme-app.escalation.test", JWKSURI: "https://acme-app.escalation.test/jwks", Enabled: true})
	require.NoError(t, err)
	authtest.GrantRole(t, auth, acme, iam.RemoteApplicationSubject(app.ID), manager)
	key, _, err := auth.MintAPIKey(ctx, iam.UserActor(founder.ID), acme, iam.NewAPIKey{Name: "manager-key", Role: manager})
	require.NoError(t, err)
	for name, actor := range map[string]iam.Actor{
		"user":                  iam.UserActor(mgr.ID),
		"api_key":               iam.APIKeyActor(key.ID),
		"remote_application":    iam.RemoteApplicationActor(app.ID),
		"delegated_local":       iam.DelegatedActor(iam.DelegatedGrant{Issuer: authtest.Issuer, Subject: mgr.ID, Permissions: []iam.Perm{org.All()}}),
		"delegated_application": iam.DelegatedActor(iam.DelegatedGrant{Issuer: app.Issuer, Subject: "customer", Permissions: []iam.Perm{org.All()}, RemoteApplicationID: app.ID, GroupID: acme.ID()}),
	} {
		t.Run(name, func(t *testing.T) {
			fresh := newSubject(t)
			require.NoError(t, assign(auth, actor, acme, fresh, member), "a covered role is grantable")
			require.NoError(t, removeMember(auth, actor, acme, fresh))
			for op, err := range map[string]error{
				"grant owner":          assign(auth, actor, acme, newSubject(t), org.Owner),
				"replace the owner":    assign(auth, actor, acme, founder, member),
				"unassign the owner":   unassign(auth, actor, acme, founder, org.Owner),
				"remove the owner":     removeMember(auth, actor, acme, founder),
				"promote itself":       assign(auth, actor, acme, mgr, org.Owner),
				"act in another group": assign(auth, actor, other, newSubject(t), member),
				"act beyond a ceiling": assign(auth, actor.Within(catalog), acme, newSubject(t), member),
			} {
				require.Error(t, err, op)
				require.True(t, errors.Is(err, iam.ErrRoleAssignmentEscalation) || errors.Is(err, iam.ErrInsufficientAuthority), "%s: %v", op, err)
			}
		})
	}
	t.Run("foreign_delegation", func(t *testing.T) {
		foreign := iam.DelegatedActor(iam.DelegatedGrant{Issuer: "https://foreign.test", Subject: mgr.ID, Permissions: []iam.Perm{org.All()}})
		require.ErrorIs(t, assign(auth, foreign, acme, newSubject(t), member), iam.ErrInsufficientAuthority)
	})
	t.Run("system", func(t *testing.T) {
		require.NoError(t, assign(auth, iam.SystemActor(), acme, newSubject(t), org.Owner))
		require.ErrorIs(t, removeMember(auth, iam.SystemActor(), other, founder), iam.ErrLastOwner)
	})
	roles, err := auth.GroupRoles(ctx, acme, []iam.Subject{founder, mgr})
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{founder: org.Owner, mgr: manager}, roles)
}

// Root is the widest scope: a root role's persona permissions apply in every
// group of that persona, for checks and for CAP/COVER alike, while root:
// permissions count only on root and never stand in for persona ones.
func TestRootRolesApplyInEveryGroup(t *testing.T) {
	rbac := authkit.NewRoles()
	org := rbac.Persona("org")
	member := org.Role("member", org.Permission("catalog", "read"))
	orgAdminRole := rbac.Root.Role("org-admin", org.All())
	bannerRole := rbac.Root.Role("banner", rbac.Root.Users.Ban)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	ctx := t.Context()
	founder, orgAdmin, banner := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	siteOwner, memberUser := authtest.NewUser(t, auth), iam.UserSubject(authtest.NewUser(t, auth).ID)
	acme := newGroup(t, auth, org.Persona, founder.ID)
	root := iam.RootGroup()
	authtest.GrantRole(t, auth, root, iam.UserSubject(orgAdmin.ID), orgAdminRole)
	authtest.GrantRole(t, auth, root, iam.UserSubject(banner.ID), bannerRole)
	authtest.GrantRole(t, auth, root, iam.UserSubject(siteOwner.ID), rbac.Root.Owner)
	can := func(u authtest.User, g iam.GroupRef, p iam.Perm) bool {
		t.Helper()
		ok, err := auth.Can(ctx, iam.UserActor(u.ID), g, p)
		require.NoError(t, err)
		return ok
	}

	require.True(t, can(orgAdmin, acme, org.Members.Manage))
	require.NoError(t, assign(auth, iam.UserActor(orgAdmin.ID), acme, memberUser, member))
	require.NoError(t, assign(auth, iam.UserActor(orgAdmin.ID), acme, memberUser, org.Owner), "org:* on root covers the org owner role")
	require.True(t, can(banner, root, iam.PermRootUsersBan))
	require.False(t, can(banner, acme, iam.PermRootUsersBan), "root permissions count only on root")
	require.False(t, can(siteOwner, acme, org.Members.Manage), "root:* never stands in for a persona permission")
	require.ErrorIs(t, assign(auth, iam.UserActor(siteOwner.ID), acme, memberUser, member), iam.ErrInsufficientAuthority)
}

// An owner manages its group over HTTP; the last owner never leaves it
// ownerless, and a manager never demotes an owner.
func TestRoleOwnerHTTPWorkflow(t *testing.T) {
	m := newOrgModel()
	manager := m.org.Role("manager", m.org.Members.Manage, m.org.Credentials.Manage, m.catalog)
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	ctx := t.Context()
	a := newAPI(t, auth)
	owner, mgr, peer := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	token, managerToken := authtest.SignIn(t, auth, owner).AccessToken, authtest.SignIn(t, auth, mgr).AccessToken
	group := newGroup(t, auth, m.org.Persona, owner.ID)
	base := "/groups/" + group.ID()
	authtest.GrantRole(t, auth, group, iam.UserSubject(mgr.ID), manager)
	put := func(token, id, role string) response {
		return a.do(request{method: http.MethodPut, path: base + "/members/" + id + "/roles/" + role, token: token})
	}
	require.Equal(t, http.StatusForbidden, put(managerToken, owner.ID, "member").status)
	require.Equal(t, http.StatusConflict, put(token, owner.ID, "member").status)
	res := put(token, owner.ID, "%20owner%20")
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.Contains(t, res.String(), `"role":"owner"`)
	res = a.do(request{method: http.MethodDelete, path: base + "/members/" + owner.ID, token: token})
	require.Equal(t, http.StatusConflict, res.status, res.String())
	require.Equal(t, "last_owner", res.code())
	app, err := auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, iam.RemoteApplication{Slug: "owner-app", Issuer: "https://owner-app.test", JWKSURI: "https://owner-app.test/jwks", Enabled: true})
	require.NoError(t, err)
	require.NoError(t, assign(auth, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), m.org.Owner))
	err = assign(auth, iam.UserActor(mgr.ID), group, iam.RemoteApplicationSubject(app.ID), m.member)
	require.True(t, errors.Is(err, iam.ErrInsufficientAuthority) || errors.Is(err, iam.ErrRoleAssignmentEscalation), "a manager cannot demote an owner application: %v", err)
	require.NoError(t, auth.DeleteRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(app.PermissionGroupID), app.Slug))
	require.Equal(t, http.StatusOK, put(token, peer.ID, "owner").status)
	require.Equal(t, http.StatusOK, put(token, peer.ID, "member").status)
	require.Equal(t, http.StatusOK, put(token, peer.ID, "owner").status)
	res = a.do(request{method: http.MethodDelete, path: base + "/members/" + owner.ID, token: token})
	require.Equal(t, http.StatusNoContent, res.status, res.String())
	allowed, err := auth.Can(ctx, iam.UserActor(peer.ID), group, m.org.Members.Manage)
	require.NoError(t, err)
	require.True(t, allowed)
}

// A bounded root admin manages root roles over HTTP, never to or over an
// owner; machine and delegated credentials never reach those routes.
func TestAdminRootRoleHTTPWorkflow(t *testing.T) {
	m := newOrgModel(authkit.APIKeys)
	adminRole := m.rbac.Root.Role("admin", m.rbac.Root.Members.All(), m.rbac.Root.Users.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		m.config(c)
		// root:members:manage needs MFA; this test is about actor kinds, not MFA.
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	ctx := t.Context()
	a := newAPI(t, auth)
	owner, admin, target := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	ownerToken, adminToken := authtest.SignIn(t, auth, owner).AccessToken, authtest.SignIn(t, auth, admin).AccessToken
	targetToken := authtest.SignIn(t, auth, target).AccessToken
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(owner.ID), m.rbac.Root.Owner)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(admin.ID), adminRole)
	call := func(method, user, role, token string, status int) {
		t.Helper()
		res := a.do(request{method: method, path: "/admin/users/" + user + "/roles/" + role, token: token})
		require.Equal(t, status, res.status, res.String())
	}
	rootRole := func(user string) iam.Role {
		t.Helper()
		roles, err := auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(user)})
		require.NoError(t, err)
		return roles[iam.UserSubject(user)]
	}

	// A bounded admin promotes to roles it covers, never to or over an owner.
	call(http.MethodPut, target.ID, "site-admin", adminToken, http.StatusNoContent)
	require.Equal(t, m.siteAdmin, rootRole(target.ID))
	call(http.MethodPut, target.ID, "owner", adminToken, http.StatusForbidden)
	call(http.MethodPut, owner.ID, "site-admin", adminToken, http.StatusForbidden)
	call(http.MethodPut, admin.ID, "site-admin", targetToken, http.StatusForbidden)
	call(http.MethodPut, target.ID, "no-such-role", ownerToken, http.StatusBadRequest)
	call(http.MethodPut, target.ID, "site-admin", "", http.StatusUnauthorized)
	call(http.MethodDelete, target.ID, "site-admin", adminToken, http.StatusNoContent)
	require.Empty(t, rootRole(target.ID))
	call(http.MethodDelete, owner.ID, "owner", ownerToken, http.StatusConflict)

	// Machine and delegated actors never reach the management plane, even
	// with the authority to act.
	_, keyToken, err := auth.MintAPIKey(ctx, iam.UserActor(owner.ID), iam.RootGroup(), iam.NewAPIKey{Name: "root-admin-key", Role: adminRole})
	require.NoError(t, err)
	delegated, err := auth.MintDelegatedAccessToken(ctx, iam.SystemActor(), iam.DelegatedAccess{Audiences: []string{authtest.Audience}, Subject: admin.ID,
		Permissions: []string{m.rbac.Root.Members.All().String(), iam.PermRootUsersRead.String()}})
	require.NoError(t, err)
	for _, token := range []string{keyToken, delegated.Value} {
		res := a.do(request{method: http.MethodPut, path: "/admin/users/" + target.ID + "/roles/site-admin", token: token})
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, res.status, res.String())
	}
	require.Empty(t, rootRole(target.ID))

	res := a.get("/admin/roles", adminToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.Contains(t, res.String(), `"site-admin"`)
	require.Contains(t, res.String(), `"owner"`)
	require.Equal(t, http.StatusForbidden, a.get("/admin/roles", targetToken).status)
}

func publicKeyPEM(t testing.TB, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// remoteApplicationToken is an application's own access token, signed with
// its key: no subject, the apitest audience. A non-nil perms narrows the
// application's stored authority.
func remoteApplicationToken(t testing.TB, signer keys.Signer, issuer string, perms []string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{"iss": issuer, "aud": []string{authtest.Audience}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	if perms != nil {
		claims["permissions"] = perms
	}
	token, err := jose.Sign(context.Background(), signer, jose.RemoteApplicationAccessTokenType, claims)
	require.NoError(t, err)
	return token
}

// An application owning a group operates its member routes with its own
// signed token, within its live authority, its group and its token's ceiling.
func TestRemoteOwnerOperatesGroupHTTP(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	ctx := t.Context()
	a := newAPI(t, auth)
	owner, peer := authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	ownerToken := authtest.SignIn(t, auth, owner).AccessToken
	group := newGroup(t, auth, m.org.Persona, owner.ID)
	other := newGroup(t, auth, m.org.Persona, owner.ID)
	signer := testkeys.RSA("remote-owner")
	app, err := auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, iam.RemoteApplication{
		Slug: "operable-owner", Issuer: "https://operable-owner.test", Enabled: true,
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: publicKeyPEM(t, signer.Public())}},
	})
	require.NoError(t, err)
	authtest.GrantRole(t, auth, group, iam.RemoteApplicationSubject(app.ID), m.org.Owner)
	mint := func(perms []string) string {
		t.Helper()
		return remoteApplicationToken(t, signer, app.Issuer, perms)
	}
	token := mint(nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	verified, err := auth.VerifyRequest(req)
	require.NoError(t, err)
	// Verification is not a lease on database authority: a change between
	// verification and mutation must be seen inside the mutation transaction.
	actor, ok := verify.ActorFromClaims(verified)
	require.True(t, ok)
	require.Equal(t, iam.ActorRemoteApplication, actor.Kind())
	authtest.GrantRole(t, auth, group, iam.RemoteApplicationSubject(app.ID), m.member)
	require.ErrorIs(t, assign(auth, actor, group, iam.UserSubject(peer.ID), m.member), iam.ErrInsufficientAuthority)
	authtest.GrantRole(t, auth, group, iam.RemoteApplicationSubject(app.ID), m.org.Owner)
	// Application authority is bound to its controlling group and its ceiling.
	require.ErrorIs(t, assign(auth, actor, other, iam.UserSubject(peer.ID), m.member), iam.ErrInsufficientAuthority)
	require.ErrorIs(t, assign(auth, actor.Within(m.catalog), group, iam.UserSubject(peer.ID), m.member), iam.ErrInsufficientAuthority)
	forged := verified
	forged.Kind = iam.ActorAPIKey
	_, ok = verify.ActorFromClaims(forged)
	require.False(t, ok)
	_, err = auth.AssignGroupRoles(ctx, iam.Actor{}, group, []iam.Subject{iam.UserSubject(peer.ID)}, m.member)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	call := func(method, path string, body any, bearer string, status int) {
		t.Helper()
		res := a.do(request{method: method, path: path, body: body, token: bearer})
		require.Equal(t, status, res.status, res.String())
	}
	members := "/groups/" + group.ID() + "/members"
	base := members + "/"
	// A signed app-self credential can manage existing users on its own group.
	call(http.MethodPost, members, map[string]string{"user_id": peer.ID, "role": "member"}, token, http.StatusOK)
	call(http.MethodPut, base+peer.ID+"/roles/owner", nil, mint([]string{m.org.Members.Manage.String()}), http.StatusForbidden)
	call(http.MethodPut, base+peer.ID+"/roles/member", nil, mint([]string{}), http.StatusForbidden)
	call(http.MethodPut, "/groups/"+other.ID()+"/members/"+peer.ID+"/roles/member", nil, token, http.StatusForbidden)
	// Full live authority cannot widen a downscoped credential when replacing
	// an existing owner, even if the requested replacement is a lesser role.
	call(http.MethodPut, base+peer.ID+"/roles/owner", nil, token, http.StatusOK)
	call(http.MethodPut, base+peer.ID+"/roles/member", nil, mint([]string{m.org.Members.Manage.String(), m.catalog.String()}), http.StatusForbidden)
	call(http.MethodDelete, base+peer.ID, nil, token, http.StatusNoContent)
	call(http.MethodDelete, base+owner.ID, nil, ownerToken, http.StatusNoContent)
	// The last native owner may leave: the remaining remote owner can restore
	// native ownership through exactly the supported signed HTTP interface.
	call(http.MethodPut, base+peer.ID+"/roles/owner", nil, token, http.StatusOK)
	call(http.MethodGet, members, nil, token, http.StatusOK)
	call(http.MethodPost, members, map[string]string{"email": "unregistered@example.test", "role": "member"}, token, http.StatusForbidden)
	// Sender metadata on a delegated credential is never app-self authority.
	delegated, err := jose.Sign(ctx, signer, jose.DelegatedAccessTokenType, jwt.MapClaims{"iss": app.Issuer, "aud": []string{authtest.Audience}, "exp": time.Now().Add(time.Minute).Unix(),
		"delegated_sub": "external-customer", "permissions": []string{m.org.All().String()}})
	require.NoError(t, err)
	res := a.do(request{method: http.MethodPut, path: base + owner.ID + "/roles/owner", token: delegated})
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, res.status, res.String())
	// A cached signature/issuer never preserves disabled application authority.
	app.Enabled = false
	_, err = auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(app.PermissionGroupID), app)
	require.NoError(t, err)
	res = a.do(request{method: http.MethodPut, path: base + owner.ID + "/roles/owner", token: token})
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, res.status, res.String())
}

// oneConnection is a replica of auth on a pool of one connection, so no
// operation may need a second one while it holds the first.
func oneConnection(t *testing.T, auth *authkit.Client) *authkit.Client {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(testdb.URL(t))
	require.NoError(t, err)
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return authtest.Replica(t, auth, authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = pool }))
}

// A deleted group keeps its state but grants nothing, at once: not to its
// members, a principal captured before, its API keys or a signed-in owner's
// session. It stops needing its owner, whose account may then go, while a
// live group still needs its own.
func TestSoftDeleteGroupRetainsStateAndReleasesOwner(t *testing.T) {
	rbac := authkit.NewRoles()
	channel := rbac.Persona("channel", authkit.APIKeys)
	postsRead := channel.Permission("posts", "read")
	reader := channel.Role("reader", postsRead)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	slot := oneConnection(t, auth)
	ctx := t.Context()
	owner, peer := authtest.NewUser(t, slot), authtest.NewUser(t, slot)
	group := newGroup(t, slot, channel.Persona, owner.ID)
	active := newGroup(t, slot, channel.Persona, peer.ID)
	_, secret, err := slot.MintAPIKey(ctx, iam.UserActor(owner.ID), group, iam.NewAPIKey{Name: "retained-key", Role: reader})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/channel", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	principal, err := slot.AuthenticateRequest(ctx, req)
	require.NoError(t, err)
	checker := principal.(hostauth.PermissionChecker)
	scope := hostauth.Scope{Authority: authtest.Issuer, ID: group.ID()}
	allowed, err := checker.Can(ctx, scope, postsRead.String())
	require.NoError(t, err)
	require.True(t, allowed)
	result, err := slot.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
	require.NoError(t, err)
	require.ErrorIs(t, result[0].Err, iam.ErrLastOwner)
	require.NoError(t, slot.DeleteGroup(ctx, group))
	deleted, err := slot.Group(ctx, group)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	require.NoError(t, slot.DeleteGroup(ctx, group), "deleting a deleted group is a no-op")
	descriptor, err := slot.Group(ctx, group)
	require.NoError(t, err)
	require.Equal(t, deleted.DeletedAt, descriptor.DeletedAt)
	allowed, err = slot.Can(ctx, iam.UserActor(owner.ID), group, postsRead)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = checker.Can(ctx, scope, postsRead.String())
	require.NoError(t, err)
	require.False(t, allowed, "captured machine principal must observe retirement without another proof")
	_, err = slot.AuthenticateRequest(ctx, req)
	require.Error(t, err, "retired group's API key is unusable on subsequent requests")
	require.ErrorIs(t, assign(slot, iam.SystemActor(), group, iam.UserSubject(peer.ID), reader), iam.ErrGroupNotFound)
	_, _, err = slot.MintAPIKey(ctx, iam.SystemActor(), group, iam.NewAPIKey{Name: "forbidden", Role: reader})
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	result, err = slot.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID, peer.ID})
	require.NoError(t, err)
	require.NoError(t, result[0].Err)
	require.ErrorIs(t, result[1].Err, iam.ErrLastOwner, "active sibling still requires its owner")
	current, err := slot.Group(ctx, active)
	require.NoError(t, err)
	require.Nil(t, current.DeletedAt)
	root, err := slot.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	require.Error(t, slot.DeleteGroup(ctx, iam.GroupByID(root.ID)))
	require.NoError(t, slot.PurgeGroup(ctx, group))
	require.NoError(t, slot.PurgeGroup(ctx, group))
	_, err = slot.Group(ctx, group)
	require.ErrorIs(t, err, iam.ErrGroupNotFound)

	t.Run("a signed-in owner loses the group at once", func(t *testing.T) {
		ctx := t.Context()
		owner := authtest.NewUser(t, auth)
		token := authtest.SignIn(t, auth, owner).AccessToken
		group := newGroup(t, auth, channel.Persona, owner.ID)
		req := httptest.NewRequest(http.MethodGet, "https://example.com/channel/"+group.ID(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		principal, err := auth.AuthenticateRequest(ctx, req)
		require.NoError(t, err)
		checker := principal.(hostauth.PermissionChecker)
		scope := hostauth.Scope{Authority: authtest.Issuer, ID: group.ID()}
		allowed, err := checker.Can(ctx, scope, postsRead.String())
		require.NoError(t, err)
		require.True(t, allowed)
		before, err := auth.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
		require.NoError(t, err)
		require.ErrorIs(t, before[0].Err, iam.ErrLastOwner)
		require.NoError(t, auth.DeleteGroup(ctx, group))
		descriptor, err := auth.Group(ctx, group)
		require.NoError(t, err)
		require.NotNil(t, descriptor.DeletedAt)
		allowed, err = checker.Can(ctx, scope, postsRead.String())
		require.NoError(t, err)
		require.False(t, allowed, "the same native principal loses group authority immediately")
		res := newAPI(t, auth).get("/groups/"+group.ID()+"/members", token)
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		after, err := auth.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})
		require.NoError(t, err)
		require.NoError(t, after[0].Err)
		retained, err := auth.Group(ctx, group)
		require.NoError(t, err)
		require.Equal(t, descriptor.DeletedAt, retained.DeletedAt)
	})

	t.Run("deleting the group and its owner at once", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		for range 8 {
			owner := authtest.NewUser(t, slot)
			group := newGroup(t, slot, channel.Persona, owner.ID)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var retireErr, deleteErr error
			wg.Go(func() { <-start; retireErr = slot.DeleteGroup(ctx, group) })
			wg.Go(func() {
				<-start
				deleteErr = opErr(slot.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID}))
			})
			close(start)
			wg.Wait()
			require.NoError(t, retireErr)
			if deleteErr != nil {
				require.ErrorIs(t, deleteErr, iam.ErrLastOwner)
			}
			require.NoError(t, opErr(slot.DeleteUsers(ctx, iam.SystemActor(), []string{owner.ID})))
			retained, err := slot.Group(ctx, group)
			require.NoError(t, err)
			require.NotNil(t, retained.DeletedAt)
		}
	})
}

// A request principal checks authority live: a role granted or removed after
// it was built counts on its next check, with no host glue.
func TestRuntimeRequestPrincipalUsesLiveAuthority(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	ctx := t.Context()
	root, err := auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	u := authtest.NewUser(t, auth)
	req := httptest.NewRequest(http.MethodGet, "https://resource.example/account", nil)
	req.Header.Set("Authorization", "Bearer "+authtest.SignIn(t, auth, u).AccessToken)
	principal, err := auth.AuthenticateRequest(ctx, req)
	require.NoError(t, err)
	require.Equal(t, u.ID, principal.Identity().Subject)
	checker := principal.(hostauth.PermissionChecker)
	scope := hostauth.Scope{Authority: authtest.Issuer, ID: root.ID}
	allowed, err := checker.Can(ctx, scope, iam.PermRootUsersRead.String())
	require.NoError(t, err)
	require.False(t, allowed)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(u.ID), m.siteAdmin)
	allowed, err = checker.Can(ctx, scope, iam.PermRootUsersRead.String())
	require.NoError(t, err)
	require.True(t, allowed, "runtime must wire live authority without host glue")
	authtest.RevokeRole(t, auth, iam.RootGroup(), iam.UserSubject(u.ID), m.siteAdmin)
	allowed, err = checker.Can(ctx, scope, iam.PermRootUsersRead.String())
	require.NoError(t, err)
	require.False(t, allowed, "same principal observes removal without reauthenticating")
}

// /capabilities lists the configured providers; /me/groups lists the caller's
// current memberships, root included, and nobody else's.
func TestCapabilitiesAndRootMembershipDiscovery(t *testing.T) {
	rbac := authkit.NewRoles()
	reader := rbac.Root.Role("reader", rbac.Root.Permission("posts", "read"))
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Registration.Verification = iam.RegistrationVerificationNone
		c.Identity.Providers = []provider.Provider{provider.Google("google-client", "secret"), provider.Discord("discord-client", "secret")}
	}))
	a := newAPI(t, auth)
	caps := a.get("/capabilities", "")
	require.Equal(t, http.StatusOK, caps.status, caps.String())
	var body map[string]json.RawMessage
	caps.decode(t, &body)
	require.NotContains(t, body, "providers")
	type provider struct {
		ID                   string `json:"id"`
		Name                 string `json:"name"`
		SupportsLogin        bool   `json:"supports_login"`
		SupportsRegistration bool   `json:"supports_registration"`
		SupportsLink         bool   `json:"supports_link"`
	}
	var providers []provider
	require.NoError(t, json.Unmarshal(body["external_login_providers"], &providers))
	require.Equal(t, []provider{{ID: "discord", Name: "Discord", SupportsLogin: true, SupportsRegistration: true, SupportsLink: true}, {ID: "google", Name: "Google", SupportsLogin: true, SupportsRegistration: true, SupportsLink: true}}, providers)
	res := a.get("/me/groups", "")
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	register := func(name string) iam.TokenSet {
		t.Helper()
		res := a.post("/register", "", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-membership-password-1"})
		require.Equal(t, http.StatusAccepted, res.status, res.String())
		var registered struct {
			Tokens iam.TokenSet `json:"token_set"`
		}
		res.decode(t, &registered)
		return registered.Tokens
	}
	alice, bob := register("membersalice"), register("membersbob")
	type membership struct {
		GroupID string `json:"group_id"`
		Persona string `json:"persona"`
		Role    string `json:"role"`
	}
	groups := func(token, query string) []membership {
		t.Helper()
		res := a.get("/me/groups"+query, token)
		require.Equal(t, http.StatusOK, res.status, res.String())
		var list struct {
			Data []membership `json:"data"`
		}
		res.decode(t, &list)
		require.NotNil(t, list.Data, "empty membership is an array, not null")
		return list.Data
	}
	require.Empty(t, groups(alice.AccessToken, ""))
	claims, err := auth.Verify(t.Context(), alice.AccessToken)
	require.NoError(t, err)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(claims.UserID), reader)
	got := groups(alice.AccessToken, "")
	require.Len(t, got, 1)
	require.NotEmpty(t, got[0].GroupID)
	require.Equal(t, "root", got[0].Persona)
	require.Equal(t, "reader", got[0].Role)
	require.Empty(t, groups(bob.AccessToken, "?user_id="+claims.UserID), "caller cannot select another user's memberships")
	authtest.RevokeRole(t, auth, iam.RootGroup(), iam.UserSubject(claims.UserID), reader)
	require.Empty(t, groups(alice.AccessToken, ""), "membership discovery reads current assignments")
}
