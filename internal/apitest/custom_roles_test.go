package apitest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	hauth "github.com/open-rails/helpers/auth"
)

const shopResource = "https://shop-api.test"

// shop is a merchant persona whose groups hold API keys, trust remote
// applications and define custom roles; groups a and b have their own
// owners. A designer composes roles from what it holds; a manager hands
// roles out.
type shop struct {
	auth                         *authkit.Client
	api                          *api
	persona                      iam.Persona
	entitlements, catalog        iam.Perm
	membersRead, credentialsRead iam.Perm
	credentialsManage            iam.Perm
	designer, manager            iam.Role
	a, b                         iam.GroupRef
	owner, other                 authtest.User
	ownerToken                   string
}

func newShop(t *testing.T, opts ...authtest.Option) shop {
	t.Helper()
	rbac := authkit.NewRoles()
	merchant := rbac.Persona("merchant", authkit.APIKeys, authkit.RemoteApplications, authkit.CustomRoles)
	s := shop{persona: merchant.Persona, membersRead: merchant.Members.Read, credentialsRead: merchant.Credentials.Read, credentialsManage: merchant.Credentials.Manage}
	s.entitlements = merchant.Permission("entitlements", "read")
	s.catalog = merchant.Permission("catalog", "read")
	merchant.Permission("payments", "refund")
	s.designer = merchant.Role("designer", merchant.Roles.Manage, s.entitlements)
	s.manager = merchant.Role("manager", merchant.Members.Manage, merchant.Credentials.Manage, s.catalog)
	opts = append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Resource = authkit.ResourceConfig{ID: shopResource, Scopes: map[string][]string{"api:merchant": {"merchant:*"}}}
	})}, opts...)
	s.auth, _ = authtest.New(t, opts...)
	s.api = newAPI(t, s.auth)
	s.owner, s.other = authtest.NewUser(t, s.auth), authtest.NewUser(t, s.auth)
	s.a = newGroup(t, s.auth, s.persona, s.owner.ID)
	s.b = newGroup(t, s.auth, s.persona, s.other.ID)
	s.ownerToken = authtest.SignIn(t, s.auth, s.owner).AccessToken
	return s
}

func (s shop) path(g iam.GroupRef, rest string) string { return "/groups/" + g.ID() + rest }

func (s shop) can(t *testing.T, who hauth.Identity, g iam.GroupRef, p iam.Perm) bool {
	t.Helper()
	ok, err := s.auth.Can(t.Context(), who, g, p)
	require.NoError(t, err)
	return ok
}

// libraryCan is what a library guarding its own routes sees for a request
// bearing token: Client.Authenticator, then Can in group g.
func (s shop) libraryCan(t *testing.T, token string, g iam.GroupRef, p iam.Perm) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, shopResource+"/v1/entitlements", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	v, err := s.auth.Authenticator().Authenticate(r)
	require.NoError(t, err)
	scope, err := s.auth.Scope(t.Context(), g)
	require.NoError(t, err)
	ok, err := v.(hauth.PermissionChecker).Can(t.Context(), scope, p.String())
	require.NoError(t, err)
	return ok
}

func (s shop) defineRole(t *testing.T, g iam.GroupRef, name string, perms ...iam.Perm) iam.Role {
	t.Helper()
	owner := s.owner
	if g == s.b {
		owner = s.other
	}
	r, err := s.auth.CreateGroupRole(t.Context(), iam.UserIdentity(owner.ID), g, iam.NewGroupRole{Name: name, Permissions: perms})
	require.NoError(t, err)
	return r.Name
}

func strs(perms ...iam.Perm) []string {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = p.String()
	}
	return out
}

// A custom role grants exactly its permissions to every kind of holder, and
// an edit reaches them all at their next request.
func TestCustomRoleGrantsLive(t *testing.T) {
	s := newShop(t)
	ctx := t.Context()

	res := s.api.post(s.path(s.a, "/roles"), s.ownerToken, map[string]any{"name": "storefront", "permissions": strs(s.entitlements, s.membersRead)})
	require.Equal(t, http.StatusCreated, res.status, res.String())
	var created iam.GroupRole
	res.decode(t, &created)
	storefront := created.Name
	require.Equal(t, "merchant:custom-storefront", storefront.String())
	require.True(t, created.Custom)
	require.Equal(t, []iam.Perm{s.entitlements, s.membersRead}, created.Grants)
	require.ElementsMatch(t, []iam.Perm{s.entitlements, s.membersRead}, created.Permissions)
	require.NotNil(t, created.CreatedAt)

	res = s.api.get(s.path(s.a, "/roles"), s.ownerToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var listed iam.ListPage[iam.GroupRole]
	res.decode(t, &listed)
	names := make([]string, len(listed.Items))
	for i, r := range listed.Items {
		names[i] = r.Name.String()
	}
	require.Equal(t, []string{"merchant:designer", "merchant:manager", "merchant:owner", "merchant:custom-storefront"}, names, "declared roles, then the group's own")
	res = s.api.get(s.path(s.a, "/roles/"+storefront.String()), s.ownerToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var got iam.GroupRole
	res.decode(t, &got)
	require.Equal(t, created.Grants, got.Grants)

	// A member holding it.
	clerk := authtest.NewUser(t, s.auth)
	res = s.api.do(request{method: http.MethodPut, path: s.path(s.a, "/members/users/"+clerk.ID), token: s.ownerToken, body: map[string]string{"role": storefront.String()}})
	require.Equal(t, http.StatusOK, res.status, res.String())
	clerkID := iam.UserIdentity(clerk.ID)
	require.True(t, s.can(t, clerkID, s.a, s.entitlements))
	require.False(t, s.can(t, clerkID, s.a, s.catalog))
	clerkToken := authtest.SignIn(t, s.auth, clerk).AccessToken
	res = s.api.get("/me/permissions?group_id="+s.a.ID(), clerkToken)
	require.Equal(t, http.StatusOK, res.status, res.String())
	var mine httpapiPermissionSet
	res.decode(t, &mine)
	require.Equal(t, storefront.String(), mine.Role)
	require.ElementsMatch(t, strs(s.entitlements, s.membersRead), mine.Permissions)

	// An API key holding it: AuthKit's own routes and a library's checks.
	res = s.api.post(s.path(s.a, "/api-keys"), s.ownerToken, map[string]string{"name": "storefront", "role": storefront.String()})
	require.Equal(t, http.StatusCreated, res.status, res.String())
	var key iam.APIKeyCreated
	res.decode(t, &key)
	require.Equal(t, []iam.Perm{s.entitlements, s.membersRead}, key.APIKey.Permissions)
	require.Equal(t, http.StatusOK, s.api.get(s.path(s.a, "/members"), key.Secret).status, "members:read admits")
	require.Equal(t, http.StatusForbidden, s.api.get(s.path(s.a, "/api-keys"), key.Secret).status, "credentials:read is not its")
	require.True(t, s.libraryCan(t, key.Secret, s.a, s.entitlements))
	require.False(t, s.libraryCan(t, key.Secret, s.a, s.catalog))

	// An edit applies to every holder at its next request.
	patch := func(perms ...iam.Perm) response {
		return s.api.do(request{method: http.MethodPatch, path: s.path(s.a, "/roles/"+storefront.String()), token: s.ownerToken, body: map[string]any{"permissions": strs(perms...)}})
	}
	res = patch(s.entitlements, s.membersRead, s.credentialsRead, s.catalog)
	require.Equal(t, http.StatusOK, res.status, res.String())
	res.decode(t, &got)
	require.Equal(t, []iam.Perm{s.entitlements, s.membersRead, s.credentialsRead, s.catalog}, got.Grants)
	require.Equal(t, http.StatusOK, s.api.get(s.path(s.a, "/api-keys"), key.Secret).status, "the same key, the next request")
	require.True(t, s.libraryCan(t, key.Secret, s.a, s.catalog))
	require.True(t, s.can(t, clerkID, s.a, s.catalog), "the same member, no new sign-in")
	resolved, err := s.auth.ResolveAPIKey(ctx, key.Secret)
	require.NoError(t, err)
	require.Contains(t, resolved.Permissions, s.catalog)

	// Removing a permission takes it as fast; the key's issuer still covers
	// the role, so the key stands.
	res = patch(s.entitlements, s.membersRead)
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.Equal(t, http.StatusForbidden, s.api.get(s.path(s.a, "/api-keys"), key.Secret).status)
	require.False(t, s.libraryCan(t, key.Secret, s.a, s.catalog))
	require.False(t, s.can(t, clerkID, s.a, s.catalog))
	require.Equal(t, http.StatusOK, s.api.get(s.path(s.a, "/members"), key.Secret).status)

	// A pattern grant covers what the catalog has under it.
	res = patch(s.persona.OwnerGrant())
	require.Equal(t, http.StatusOK, res.status, res.String())
	require.True(t, s.libraryCan(t, key.Secret, s.a, s.catalog))
	require.True(t, s.can(t, clerkID, s.a, s.catalog))
}

// httpapiPermissionSet is GET /me/permissions' answer.
type httpapiPermissionSet struct {
	GroupID     string   `json:"group_id"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// Defining, changing and handing out a custom role never grants more than
// the caller holds.
func TestCustomRoleEscalation(t *testing.T) {
	s := newShop(t)
	ctx := t.Context()
	designer, manager := authtest.NewUser(t, s.auth), authtest.NewUser(t, s.auth)
	authtest.GrantRole(t, s.auth, s.a, iam.UserSubject(designer.ID), s.designer)
	authtest.GrantRole(t, s.auth, s.a, iam.UserSubject(manager.ID), s.manager)
	designerToken, managerToken := authtest.SignIn(t, s.auth, designer).AccessToken, authtest.SignIn(t, s.auth, manager).AccessToken
	create := func(token, name string, perms ...string) response {
		return s.api.post(s.path(s.a, "/roles"), token, map[string]any{"name": name, "permissions": perms})
	}

	res := create(designerToken, "reader", s.entitlements.String())
	require.Equal(t, http.StatusCreated, res.status, res.String())
	reader := roleText(t, "merchant:custom-reader")
	for _, perms := range [][]string{{s.catalog.String()}, {"merchant:*"}, {"merchant:entitlements:*"}, {s.entitlements.String(), "merchant:payments:refund"}} {
		res = create(designerToken, "wider", perms...)
		require.Equal(t, http.StatusForbidden, res.status, "%v: %s", perms, res)
		require.Equal(t, "role_assignment_escalation", res.code(), perms)
	}
	for name, perms := range map[string][]string{
		"unknown permission": {"merchant:nope:read"}, "another persona's": {"root:users:read"}, "bare *": {"*"},
		"none": {}, "mid-glob": {"merchant:*:read"},
	} {
		res = create(s.ownerToken, "odd", perms...)
		require.Equal(t, http.StatusBadRequest, res.status, "%s: %s", name, res)
		require.Equal(t, "invalid_request", res.code(), name)
	}
	for _, name := range []string{"Bad", "", "with space", "-x", string(make([]byte, 65))} {
		res = create(s.ownerToken, name, s.entitlements.String())
		require.Equal(t, http.StatusBadRequest, res.status, "%q: %s", name, res)
	}
	res = create(s.ownerToken, "reader", s.catalog.String())
	require.Equal(t, http.StatusConflict, res.status, res.String())
	require.Equal(t, "role_exists", res.code())
	res = create(managerToken, "mine", s.catalog.String())
	require.Equal(t, http.StatusForbidden, res.status, "no roles:manage")

	// A declared role is the app's.
	res = s.api.do(request{method: http.MethodPatch, path: s.path(s.a, "/roles/merchant:manager"), token: s.ownerToken, body: map[string]any{"permissions": strs(s.catalog)}})
	require.Equal(t, http.StatusConflict, res.status, res.String())
	require.Equal(t, "role_not_editable", res.code())
	require.Equal(t, http.StatusConflict, s.api.do(request{method: http.MethodDelete, path: s.path(s.a, "/roles/merchant:owner"), token: s.ownerToken}).status)

	// An edit is a grant: the designer covers neither a wider set nor, once
	// a key holds the role, handing it to keys.
	update := func(token string, role iam.Role, perms ...string) response {
		return s.api.do(request{method: http.MethodPatch, path: s.path(s.a, "/roles/"+role.String()), token: token, body: map[string]any{"permissions": perms}})
	}
	res = update(designerToken, reader, s.entitlements.String(), s.catalog.String())
	require.Equal(t, http.StatusForbidden, res.status, res.String())
	require.Equal(t, "role_assignment_escalation", res.code())
	_, _, err := createKey(s.auth, ctx, iam.UserIdentity(s.owner.ID), s.a, iam.NewAPIKey{Name: "reader", Role: reader})
	require.NoError(t, err)
	res = update(designerToken, reader, s.entitlements.String())
	require.Equal(t, http.StatusForbidden, res.status, res.String())
	require.Equal(t, "insufficient_authority", res.code(), "a held role takes what hands it out")
	res = s.api.do(request{method: http.MethodDelete, path: s.path(s.a, "/roles/"+reader.String()), token: designerToken})
	require.Equal(t, http.StatusForbidden, res.status, res.String())

	// Handing it out takes covering it: the manager hands out roles but holds
	// no entitlements.
	member := authtest.NewUser(t, s.auth)
	res = s.api.do(request{method: http.MethodPut, path: s.path(s.a, "/members/users/"+member.ID), token: managerToken, body: map[string]string{"role": reader.String()}})
	require.Equal(t, http.StatusForbidden, res.status, res.String())
	require.Equal(t, "role_assignment_escalation", res.code())
	res = s.api.post(s.path(s.a, "/api-keys"), managerToken, map[string]string{"name": "x", "role": reader.String()})
	require.Equal(t, http.StatusForbidden, res.status, res.String())
	require.Equal(t, "role_assignment_escalation", res.code())

	// The owner widens a role a manager's key holds: the key now exceeds its
	// issuer, so the credential sweep revokes it.
	narrow := s.defineRole(t, s.a, "narrow", s.catalog)
	_, managerKey, err := createKey(s.auth, ctx, iam.UserIdentity(manager.ID), s.a, iam.NewAPIKey{Name: "narrow", Role: narrow})
	require.NoError(t, err)
	_, err = s.auth.UpdateGroupRole(ctx, iam.UserIdentity(s.owner.ID), s.a, narrow, iam.GroupRoleUpdate{Permissions: []iam.Perm{s.catalog, s.entitlements}})
	require.NoError(t, err)
	_, err = s.auth.ResolveAPIKey(ctx, managerKey)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)

	// Removing a permission from a role revokes what its holders issued and
	// no longer cover.
	keymaster := s.defineRole(t, s.a, "keymaster", s.credentialsManage, s.entitlements)
	km := authtest.NewUser(t, s.auth)
	authtest.GrantRole(t, s.auth, s.a, iam.UserSubject(km.ID), keymaster)
	_, kmKey, err := createKey(s.auth, ctx, iam.UserIdentity(km.ID), s.a, iam.NewAPIKey{Name: "reader", Role: reader})
	require.NoError(t, err)
	_, err = s.auth.UpdateGroupRole(ctx, iam.UserIdentity(s.owner.ID), s.a, keymaster, iam.GroupRoleUpdate{Permissions: []iam.Perm{s.credentialsManage}})
	require.NoError(t, err)
	_, err = s.auth.ResolveAPIKey(ctx, kmKey)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)
}

// roleText reads role text.
func roleText(t *testing.T, text string) iam.Role {
	t.Helper()
	var r iam.Role
	require.NoError(t, r.UnmarshalText([]byte(text)))
	return r
}

// A custom role is its group's: another group neither sees nor holds it, and
// may define its own of the same name.
func TestCustomRoleStaysInItsGroup(t *testing.T) {
	s := newShop(t)
	ctx := t.Context()
	storefront := s.defineRole(t, s.a, "storefront", s.entitlements)
	otherToken := authtest.SignIn(t, s.auth, s.other).AccessToken

	res := s.api.get(s.path(s.b, "/roles/"+storefront.String()), otherToken)
	require.Equal(t, http.StatusNotFound, res.status, res.String())
	require.Equal(t, "role_not_found", res.code())
	roles, err := s.auth.ListGroupRoles(ctx, s.b)
	require.NoError(t, err)
	require.False(t, slices.ContainsFunc(roles, func(r iam.GroupRole) bool { return r.Custom }))
	require.Equal(t, http.StatusForbidden, s.api.get(s.path(s.a, "/roles/"+storefront.String()), otherToken).status, "not a's member")

	other := iam.UserIdentity(s.other.ID)
	bystander := authtest.NewUser(t, s.auth)
	_, err = s.auth.SetGroupRole(ctx, other, s.b, iam.UserSubject(bystander.ID), storefront)
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	_, _, err = createKey(s.auth, ctx, other, s.b, iam.NewAPIKey{Name: "x", Role: storefront})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	_, err = s.auth.CreateInvitation(ctx, other, s.b, iam.NewInvitation{Role: storefront})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	_, err = s.auth.UpdateGroupRole(ctx, other, s.b, storefront, iam.GroupRoleUpdate{Permissions: []iam.Perm{s.catalog}})
	require.ErrorIs(t, err, iam.ErrRoleNotFound)
	_, err = s.auth.UpdateGroupRole(ctx, other, s.a, storefront, iam.GroupRoleUpdate{Permissions: []iam.Perm{s.catalog}})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)

	// a's holders act in a only.
	clerk := authtest.NewUser(t, s.auth)
	authtest.GrantRole(t, s.auth, s.a, iam.UserSubject(clerk.ID), storefront)
	_, keyA, err := createKey(s.auth, ctx, iam.UserIdentity(s.owner.ID), s.a, iam.NewAPIKey{Name: "a", Role: storefront})
	require.NoError(t, err)
	require.True(t, s.can(t, iam.UserIdentity(clerk.ID), s.a, s.entitlements))
	require.False(t, s.can(t, iam.UserIdentity(clerk.ID), s.b, s.entitlements))
	require.False(t, s.libraryCan(t, keyA, s.b, s.entitlements))

	// b's own storefront is another role under the same text.
	same := s.defineRole(t, s.b, "storefront", s.catalog)
	require.Equal(t, storefront, same)
	authtest.GrantRole(t, s.auth, s.b, iam.UserSubject(bystander.ID), same)
	require.True(t, s.can(t, iam.UserIdentity(bystander.ID), s.b, s.catalog))
	require.False(t, s.can(t, iam.UserIdentity(bystander.ID), s.b, s.entitlements))
	require.False(t, s.can(t, iam.UserIdentity(clerk.ID), s.a, s.catalog), "a's definition is a's")
	require.NoError(t, s.auth.DeleteGroupRole(ctx, other, s.b, same))
	require.True(t, s.can(t, iam.UserIdentity(clerk.ID), s.a, s.entitlements), "deleting b's leaves a's")
	require.True(t, s.libraryCan(t, keyA, s.a, s.entitlements))
}

// eventSink is a host's Deps.OnEvent.
type eventSink struct {
	mu     sync.Mutex
	events []iam.Event
}

func (e *eventSink) hook(_ context.Context, ev iam.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	return nil
}

func (e *eventSink) await(t *testing.T, match func(iam.Event) bool, what string) iam.Event {
	t.Helper()
	var found iam.Event
	require.Eventually(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		i := slices.IndexFunc(e.events, match)
		if i >= 0 {
			found = e.events[i]
		}
		return i >= 0
	}, time.Minute, 50*time.Millisecond, "no %s event", what)
	return found
}

// Deleting a custom role takes it from every holder at once; a role later
// given the same name starts with none.
func TestCustomRoleDeleteRevokes(t *testing.T) {
	sink := &eventSink{}
	s := newShop(t, authtest.WithDeps(func(d *authkit.Deps) { d.OnEvent = sink.hook }))
	ctx := t.Context()
	require.NoError(t, s.auth.Start(ctx))
	owner := iam.UserIdentity(s.owner.ID)
	storefront := s.defineRole(t, s.a, "storefront", s.entitlements, s.membersRead)

	clerk := authtest.NewUser(t, s.auth)
	authtest.GrantRole(t, s.auth, s.a, iam.UserSubject(clerk.ID), storefront)
	key, secret, err := createKey(s.auth, ctx, owner, s.a, iam.NewAPIKey{Name: "storefront", Role: storefront})
	require.NoError(t, err)
	link, err := s.auth.CreateInvitation(ctx, owner, s.a, iam.NewInvitation{Role: storefront})
	require.NoError(t, err)
	signer := testkeys.RSA("shop-app")
	app, err := s.auth.UpsertRemoteApplication(ctx, owner, s.a, iam.RemoteApplication{
		Issuer: "https://shop-app.test", Enabled: true, RoleMap: map[string]iam.Role{"viewer": storefront},
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: publicKeyPEM(t, signer.Public())}},
	})
	require.NoError(t, err)
	_, err = s.auth.SetGroupRole(ctx, owner, s.a, iam.RemoteApplicationSubject(app.ID), storefront)
	require.NoError(t, err)
	require.True(t, s.can(t, iam.ApplicationIdentity(app.ID), s.a, s.entitlements))
	require.Equal(t, http.StatusOK, s.api.get(s.path(s.a, "/members"), secret).status)

	res := s.api.do(request{method: http.MethodDelete, path: s.path(s.a, "/roles/"+storefront.String()), token: s.ownerToken})
	require.Equal(t, http.StatusNoContent, res.status, res.String())

	require.False(t, s.can(t, iam.UserIdentity(clerk.ID), s.a, s.entitlements))
	require.Equal(t, iam.Role{}, roleOfIn(t, s.auth, s.a, iam.UserSubject(clerk.ID)))
	_, err = s.auth.ResolveAPIKey(ctx, secret)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)
	require.Equal(t, http.StatusUnauthorized, s.api.get(s.path(s.a, "/members"), secret).status)
	keys, err := s.auth.ListAPIKeys(ctx, s.a, iam.PageRequest{})
	require.NoError(t, err)
	require.NotNil(t, keys.Items[slices.IndexFunc(keys.Items, func(k iam.APIKey) bool { return k.ID == key.ID })].RevokedAt)
	invitations, err := s.auth.ListInvitations(ctx, s.a, iam.PageRequest{})
	require.NoError(t, err)
	require.NotNil(t, invitations.Items[slices.IndexFunc(invitations.Items, func(i iam.Invitation) bool { return i.ID == link.Invitation.ID })].RevokedAt)
	require.False(t, s.can(t, iam.ApplicationIdentity(app.ID), s.a, s.entitlements))
	stored, err := s.auth.RemoteApplication(ctx, iam.AppByID(app.ID))
	require.NoError(t, err)
	require.True(t, stored.Role.IsZero())
	require.Empty(t, stored.RoleMap)
	_, err = s.auth.GroupRole(ctx, s.a, storefront)
	require.ErrorIs(t, err, iam.ErrRoleNotFound)
	require.Equal(t, http.StatusNoContent, s.api.do(request{method: http.MethodDelete, path: s.path(s.a, "/roles/"+storefront.String()), token: s.ownerToken}).status, "idempotent")

	again := s.defineRole(t, s.a, "storefront", s.entitlements)
	require.Equal(t, storefront, again)
	require.False(t, s.can(t, iam.UserIdentity(clerk.ID), s.a, s.entitlements), "a new role of the same name has no holders")

	// The audit trail: the definition, then each holder's loss before the
	// deletion.
	inA := func(kind iam.EventKind) func(iam.Event) bool {
		return func(e iam.Event) bool { return e.Kind == kind && e.GroupID == s.a.ID() && e.Role == storefront }
	}
	created := sink.await(t, inA(iam.EventGroupRoleCreated), "group.role_created")
	require.Equal(t, s.owner.ID, created.SubjectID)
	require.Equal(t, s.persona, created.Persona)
	require.Equal(t, "merchant:entitlements:read merchant:members:read", created.Current)
	deleted := sink.await(t, inA(iam.EventGroupRoleDeleted), "group.role_deleted")
	require.Equal(t, "merchant:entitlements:read merchant:members:read", deleted.Previous)
	require.Empty(t, deleted.Current)
	sink.await(t, func(e iam.Event) bool {
		return e.Kind == iam.EventRoleRevoked && e.UserID == clerk.ID && e.Previous == storefront.String()
	}, "role.revoked for the member")
	sink.await(t, func(e iam.Event) bool {
		return e.Kind == iam.EventRoleRevoked && e.ApplicationID == app.ID && e.Previous == storefront.String()
	}, "role.revoked for the application")
}

// A trusted issuer's token acts within its application's custom role, read
// live.
func TestCustomRoleRemoteApplication(t *testing.T) {
	s := newShop(t)
	ctx := t.Context()
	owner := iam.UserIdentity(s.owner.ID)
	integration := s.defineRole(t, s.a, "integration", s.entitlements)
	signer := testkeys.RSA("shop-issuer")
	app, err := s.auth.UpsertRemoteApplication(ctx, owner, s.a, iam.RemoteApplication{
		Issuer: "https://shop-issuer.test", Enabled: true, RoleMap: map[string]iam.Role{"viewer": integration},
		PublicKeys: []iam.RemoteApplicationKey{{KID: signer.KID(), PublicKeyPEM: publicKeyPEM(t, signer.Public())}},
	})
	require.NoError(t, err)
	_, err = s.auth.SetGroupRole(ctx, owner, s.a, iam.RemoteApplicationSubject(app.ID), integration)
	require.NoError(t, err)
	stored, err := s.auth.RemoteApplication(ctx, iam.AppByID(app.ID))
	require.NoError(t, err)
	require.Equal(t, integration, stored.Role)
	require.Equal(t, []iam.Perm{s.entitlements}, stored.Permissions, "the ceiling is its custom role")

	token := func(claims map[string]any) string {
		t.Helper()
		now := time.Now()
		base := map[string]any{"iss": app.Issuer, "aud": []string{shopResource}, "sub": "customer-1", "client_id": "shop", "iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(), "jti": uuid.NewString(), "scope": "api:merchant", "auth_time": now.Unix()}
		for k, v := range claims {
			base[k] = v
		}
		tok, err := jose.Sign(ctx, signer, jose.ResourceAccessTokenType, base)
		require.NoError(t, err)
		return tok
	}
	asked := map[string]any{"permissions": strs(s.entitlements, s.catalog)}
	require.True(t, s.libraryCan(t, token(asked), s.a, s.entitlements))
	require.False(t, s.libraryCan(t, token(asked), s.a, s.catalog), "outside its application's role")
	require.True(t, s.can(t, iam.ApplicationIdentity(app.ID), s.a, s.entitlements))
	require.False(t, s.can(t, iam.ApplicationIdentity(app.ID), s.a, s.catalog))
	viewer := map[string]any{"roles": []string{"viewer"}}
	require.True(t, s.libraryCan(t, token(viewer), s.a, s.entitlements), "its role_map names the custom role")
	require.False(t, s.libraryCan(t, token(viewer), s.a, s.catalog))

	_, err = s.auth.UpdateGroupRole(ctx, owner, s.a, integration, iam.GroupRoleUpdate{Permissions: []iam.Perm{s.entitlements, s.catalog}})
	require.NoError(t, err)
	require.True(t, s.libraryCan(t, token(asked), s.a, s.catalog), "the edit, at the next request")
	require.True(t, s.libraryCan(t, token(viewer), s.a, s.catalog))
	require.True(t, s.can(t, iam.ApplicationIdentity(app.ID), s.a, s.catalog))
	require.False(t, s.libraryCan(t, token(asked), s.b, s.entitlements), "only in its group")

	require.NoError(t, s.auth.DeleteGroupRole(ctx, owner, s.a, integration))
	require.False(t, s.libraryCan(t, token(asked), s.a, s.entitlements))
	require.False(t, s.libraryCan(t, token(viewer), s.a, s.entitlements))
}

// A custom role needs MFA when its permissions do: never a machine's, and a
// change to one held without a second factor is refused.
func TestCustomRoleMFA(t *testing.T) {
	rbac := authkit.NewRoles()
	merchant := rbac.Persona("merchant", authkit.APIKeys, authkit.CustomRoles)
	entitlements := merchant.Permission("entitlements", "read")
	refund := merchant.Permission("payments", "refund")
	merchant.RequireMFA(refund)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	ctx := t.Context()
	owner := authtest.NewUser(t, auth)
	authtest.EnrollTOTP(t, auth, owner)
	g := newGroup(t, auth, merchant.Persona, owner.ID)
	sys := iam.SystemIdentity()
	define := func(name string, perms ...iam.Perm) iam.GroupRole {
		r, err := auth.CreateGroupRole(ctx, sys, g, iam.NewGroupRole{Name: name, Permissions: perms})
		require.NoError(t, err)
		return r
	}

	refunds := define("refunds", refund)
	require.True(t, refunds.RequiresMFA)
	_, _, err := createKey(auth, ctx, sys, g, iam.NewAPIKey{Name: "x", Role: refunds.Name})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "a key presents no second factor")
	plain := authtest.NewUser(t, auth)
	_, err = auth.SetGroupRole(ctx, sys, g, iam.UserSubject(plain.ID), refunds.Name)
	require.ErrorIs(t, err, iam.ErrSubjectMFARequired)

	reader := define("reader", entitlements)
	_, _, err = createKey(auth, ctx, sys, g, iam.NewAPIKey{Name: "reader", Role: reader.Name})
	require.NoError(t, err)
	_, err = auth.UpdateGroupRole(ctx, sys, g, reader.Name, iam.GroupRoleUpdate{Permissions: []iam.Perm{entitlements, refund}})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "a key holds it")

	staff := define("staff", entitlements)
	authtest.GrantRole(t, auth, g, iam.UserSubject(plain.ID), staff.Name)
	_, err = auth.UpdateGroupRole(ctx, sys, g, staff.Name, iam.GroupRoleUpdate{Permissions: []iam.Perm{refund}})
	require.ErrorIs(t, err, iam.ErrSubjectMFARequired, "a holder has no second factor")
	authtest.EnrollTOTP(t, auth, plain)
	updated, err := auth.UpdateGroupRole(ctx, sys, g, staff.Name, iam.GroupRoleUpdate{Permissions: []iam.Perm{refund}})
	require.NoError(t, err)
	require.True(t, updated.RequiresMFA)
}

// A persona without CustomRoles has no custom roles and no routes to make
// them.
func TestCustomRolesNeedPersonaOptIn(t *testing.T) {
	m := newOrgModel()
	auth, _ := authtest.New(t, authtest.WithConfig(m.config))
	owner := authtest.NewUser(t, auth)
	g := newGroup(t, auth, m.org.Persona, owner.ID)
	_, err := auth.CreateGroupRole(t.Context(), iam.SystemIdentity(), g, iam.NewGroupRole{Name: "x", Permissions: []iam.Perm{m.catalog}})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = auth.Role("org:custom-x")
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	for _, r := range auth.Routes() {
		require.False(t, r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/groups/{group_id}/roles"), "%s %s is mounted", r.Method, r.Path)
	}
	a := newAPI(t, auth)
	res := a.post("/groups/"+g.ID()+"/roles", authtest.SignIn(t, auth, owner).AccessToken, map[string]any{"name": "x", "permissions": []string{m.catalog.String()}})
	require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, res.status, res.String())
}
