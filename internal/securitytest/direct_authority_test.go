package securitytest

import (
	"context"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func withDirectAuthority(c *authkit.Config) {
	r := authkit.NewRoles(authkit.APIKeys)
	app := r.Persona("app", authkit.APIKeys)
	moderate := app.Permission("comments", "moderate")
	app.Role("moderator", moderate)
	r.Root.Role("global-moderator", moderate)
	c.Roles = r
}

func TestSecurityDirectAuthority(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withDirectAuthority))
	person := h.newAccount("direct")
	tokens := h.login(person)
	grantRole(t, h.auth, iam.RootGroup(), iam.UserSubject(person.id), "global-moderator")
	persona, err := h.auth.Persona("app")
	require.NoError(t, err)
	appA, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
	require.NoError(t, err)
	appB, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
	require.NoError(t, err)
	scopeA, err := h.auth.Scope(ctx, iam.GroupByID(appA.ID))
	require.NoError(t, err)
	scopeB, err := h.auth.Scope(ctx, iam.GroupByID(appB.ID))
	require.NoError(t, err)
	v, err := h.auth.Authenticator().Authenticate(bearerRequest(tokens.AccessToken)())
	require.NoError(t, err)
	direct, ok := v.(auth.DirectPermissionChecker)
	require.True(t, ok)
	const permission = "app:comments:moderate"
	allowed, err := v.(auth.PermissionChecker).Can(ctx, scopeB, permission)
	require.NoError(t, err)
	require.True(t, allowed, "control: existing inherited Can remains compatible")
	allowed, err = direct.CanDirect(ctx, scopeB, permission)
	require.NoError(t, err)
	require.False(t, allowed, "root grant is not a direct app grant")
	query := func(group string, direct bool) []string {
		path := "/me/permissions?group_id=" + group
		if direct {
			path += "&direct=true"
		}
		response := h.get(path, tokens.AccessToken)
		require.Equal(t, 200, response.status, response.String())
		var out struct {
			Permissions []string `json:"permissions"`
		}
		response.json(t, &out)
		return out.Permissions
	}
	require.Contains(t, query(appB.ID, false), permission, "default retains inherited permissions")
	require.NotContains(t, query(appB.ID, true), permission, "direct UI must exclude root-only grants")
	grantRole(t, h.auth, iam.GroupByID(appA.ID), iam.UserSubject(person.id), "moderator")
	require.Contains(t, query(appA.ID, true), permission)
	require.NotContains(t, query(appB.ID, true), permission)
	allowed, err = direct.CanDirect(ctx, scopeA, permission)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = direct.CanDirect(ctx, scopeB, permission)
	require.NoError(t, err)
	require.False(t, allowed)
	allowed, err = direct.CanDirect(ctx, auth.Scope{Authority: "https://foreign.test", ID: appA.ID}, permission)
	require.NoError(t, err)
	require.False(t, allowed)
	perm, err := h.auth.Permission(permission)
	require.NoError(t, err)
	limited := iam.Within(iam.UserIdentity(person.id))
	allowed, err = h.auth.CanDirect(ctx, limited, iam.GroupByID(appA.ID), perm)
	require.NoError(t, err)
	require.False(t, allowed, "direct grants do not erase credential ceilings")
	_, key, err := createKey(h.auth, ctx, iam.SystemIdentity(), iam.GroupByID(appA.ID), iam.NewAPIKey{Name: "app-a", Role: roleIn(t, h.auth, iam.GroupByID(appA.ID), "moderator")})
	require.NoError(t, err)
	keyVerified, err := h.auth.Authenticator().Authenticate(bearerRequest(key)())
	require.NoError(t, err)
	keyDirect := keyVerified.(auth.DirectPermissionChecker)
	allowed, err = keyDirect.CanDirect(ctx, scopeA, permission)
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = keyDirect.CanDirect(ctx, scopeB, permission)
	require.NoError(t, err)
	require.False(t, allowed, "an app-bound key cannot act in its sibling")
	_, err = h.auth.RevokeAccountSessions(ctx, iam.SystemIdentity(), person.id)
	require.NoError(t, err)
	allowed, err = direct.CanDirect(ctx, scopeA, permission)
	require.ErrorIs(t, err, auth.ErrRevoked)
	require.False(t, allowed)
}

func TestSecurityDirectResourceAuthority(t *testing.T) {
	ctx := t.Context()
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withGroupBound))
	person := h.newAccount("directresource")
	persona, err := h.auth.Persona("merchant")
	require.NoError(t, err)
	group, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
	require.NoError(t, err)
	other, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: persona})
	require.NoError(t, err)
	ref := iam.GroupByID(group.ID)
	grantRole(t, h.auth, ref, iam.UserSubject(person.id), "support")
	token := h.exchanged(h.login(person).AccessToken, group.ID, nil)
	v, err := h.auth.Authenticator().Authenticate(bearerRequest(token)())
	require.NoError(t, err)
	direct, ok := v.(auth.DirectPermissionChecker)
	require.True(t, ok)
	scope, err := h.auth.Scope(ctx, ref)
	require.NoError(t, err)
	allowed, err := direct.CanDirect(ctx, scope, merchantRefund)
	require.NoError(t, err)
	require.True(t, allowed)
	otherScope, err := h.auth.Scope(ctx, iam.GroupByID(other.ID))
	require.NoError(t, err)
	allowed, err = direct.CanDirect(ctx, otherScope, merchantRefund)
	require.NoError(t, err)
	require.False(t, allowed, "resource credential remains pinned to its group")
	_, err = h.auth.RevokeAccountSessions(ctx, iam.SystemIdentity(), person.id)
	require.NoError(t, err)
	allowed, err = direct.CanDirect(ctx, scope, merchantRefund)
	require.ErrorIs(t, err, auth.ErrRevoked)
	require.False(t, allowed)
}
