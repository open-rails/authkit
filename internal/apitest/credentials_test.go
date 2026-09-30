package apitest_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// credentialOrg is an org persona with API keys and its group acme, owned by
// founder: members read the catalog, managers issue members, and root
// inviters send registration invites.
type credentialOrg struct {
	auth                   *authkit.Client
	acme                   iam.GroupRef
	acmeID                 string
	founder                authtest.User
	read                   iam.Perm
	member, manager, owner iam.Role
	inviter                iam.Role
	changedCatalog         *authkit.Roles
}

// credentialRoles declares the org model; audit adds a root role, a changed
// catalog every Client booted on it re-checks credentials against.
func credentialRoles(audit bool) (*authkit.Roles, credentialOrg) {
	rbac := authkit.NewRoles()
	org := rbac.Persona("org", authkit.APIKeys)
	var o credentialOrg
	o.read = org.Permission("catalog", "read")
	o.owner = org.Owner
	o.member = org.Role("member", o.read)
	o.manager = org.Role("manager", org.Members.Manage, org.Credentials.Manage, o.read)
	o.inviter = rbac.Root.Role("inviter", rbac.Root.Users.Invite)
	if audit {
		rbac.Root.Role("auditor", rbac.Root.Users.Read)
	}
	return rbac, o
}

func newCredentialOrg(t *testing.T) credentialOrg {
	t.Helper()
	catalog, o := credentialRoles(false)
	o.changedCatalog, _ = credentialRoles(true)
	o.auth, _ = authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = catalog
		c.TwoFactor.Mode = iam.TwoFactorDisabled
	}))
	o.founder = authtest.NewUser(t, o.auth)
	owner := iam.UserSubject(o.founder.ID)
	g, err := o.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: o.member.Persona(), Owner: &owner})
	require.NoError(t, err)
	o.acmeID, o.acme = g.ID, iam.GroupByID(g.ID)
	return o
}

func TestCredentialIssuance(t *testing.T) {
	o := newCredentialOrg(t)
	auth, ctx := o.auth, t.Context()
	manager, member, inviter := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, o.acme, iam.UserSubject(manager.ID), o.manager)
	authtest.GrantRole(t, auth, o.acme, iam.UserSubject(member.ID), o.member)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(inviter.ID), o.inviter)
	mgr := iam.UserActor(manager.ID)

	// A user issues what it covers and is recorded as the creator.
	key, token, err := auth.MintAPIKey(ctx, mgr, o.acme, iam.NewAPIKey{Name: " ci ", Role: o.member})
	require.NoError(t, err)
	require.Equal(t, iam.APIKey{ID: key.ID, LookupID: key.LookupID, Name: "ci", Role: o.member, Permissions: []iam.Perm{o.read}, CreatedBy: manager.ID, CreatedAt: key.CreatedAt}, key)
	principal, err := auth.ResolveAPIKey(ctx, token)
	require.NoError(t, err)
	require.Equal(t, key.ID, principal.ID)
	require.Equal(t, key.LookupID, principal.LookupID)
	require.Equal(t, iam.Group{ID: o.acmeID, Persona: o.member.Persona(), CreatedAt: principal.Group.CreatedAt}, principal.Group)
	require.False(t, principal.Group.CreatedAt.IsZero())
	require.Equal(t, authtest.Issuer, principal.Issuer)
	require.Equal(t, o.member, principal.Role)
	require.Equal(t, []iam.Perm{o.read}, principal.Permissions)
	require.Nil(t, principal.ExpiresAt)
	link, err := auth.CreateInviteLink(ctx, mgr, o.acme, iam.NewInviteLink{Role: o.member})
	require.NoError(t, err)
	require.NotEmpty(t, link.Code)

	// No escalation, and no capability means no issuance.
	_, _, err = auth.MintAPIKey(ctx, mgr, o.acme, iam.NewAPIKey{Name: "owner", Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = auth.CreateInviteLink(ctx, mgr, o.acme, iam.NewInviteLink{Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, _, err = auth.MintAPIKey(ctx, iam.UserActor(member.ID), o.acme, iam.NewAPIKey{Name: "member", Role: o.member})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	var nobody iam.Role
	require.NoError(t, nobody.UnmarshalText([]byte("org:nobody")))
	_, _, err = auth.MintAPIKey(ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "unknown", Role: nobody})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "the system skips authority, never role validity")

	// Machine actors never issue credentials, whatever authority they hold.
	managerKey, _, err := auth.MintAPIKey(ctx, iam.UserActor(o.founder.ID), o.acme, iam.NewAPIKey{Name: "manager-key", Role: o.manager})
	require.NoError(t, err)
	for name, a := range map[string]iam.Actor{
		"zero":               {},
		"api_key":            iam.APIKeyActor(managerKey.ID),
		"remote_application": iam.RemoteApplicationActor(uuid.NewString()),
		"delegated":          iam.DelegatedActor(iam.DelegatedGrant{Issuer: authtest.Issuer, Subject: manager.ID, Permissions: []iam.Perm{o.member.Persona().OwnerGrant()}}),
	} {
		_, _, err := auth.MintAPIKey(ctx, a, o.acme, iam.NewAPIKey{Name: name, Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
		_, err = auth.CreateInviteLink(ctx, a, o.acme, iam.NewInviteLink{Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
		_, err = auth.CreateAccountInvite(ctx, a, iam.NewAccountInvite{Email: name + "@machine.test", Group: o.acme, Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
	}

	// Revoking needs the authority to issue, from any actor kind.
	ok, err := auth.RevokeAPIKey(ctx, iam.UserActor(member.ID), o.acme, key.ID)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	require.False(t, ok)
	ok, err = auth.RevokeAPIKey(ctx, iam.APIKeyActor(managerKey.ID), o.acme, key.ID)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = auth.ResolveAPIKey(ctx, token)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)
	ok, err = auth.RevokeAPIKey(ctx, mgr, o.acme, key.ID)
	require.NoError(t, err)
	require.False(t, ok, "no live key")
	require.ErrorIs(t, auth.RevokeInviteLink(ctx, iam.UserActor(member.ID), o.acme, link.ID), iam.ErrInsufficientAuthority)
	require.NoError(t, auth.RevokeInviteLink(ctx, mgr, o.acme, link.ID))
	require.ErrorIs(t, auth.RevokeInviteLink(ctx, mgr, o.acme, link.ID), iam.ErrInviteLinkNotFound)

	// Registration invites: plain needs root:users:invite, a role-carrying one
	// the group's members:manage and coverage of the role.
	_, err = auth.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "plain@credentials.test"})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = auth.CreateAccountInvite(ctx, iam.UserActor(inviter.ID), iam.NewAccountInvite{Email: "plain@credentials.test"})
	require.NoError(t, err)
	_, err = auth.CreateAccountInvite(ctx, iam.UserActor(inviter.ID), iam.NewAccountInvite{Email: "join@credentials.test", Group: o.acme, Role: o.member})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = auth.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "join@credentials.test", Group: o.acme, Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = auth.CreateAccountInvite(ctx, mgr, iam.NewAccountInvite{Email: "join@credentials.test", Role: o.member})
	requireIAMCode(t, err, "invalid_invite") // a role needs a group

	// The system issues with no creator, and no sweep takes its credentials:
	// not a creator's (a ban) nor the whole site's (a changed root catalog at
	// boot).
	opKey, opToken, err := auth.MintAPIKey(ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "system", Role: o.owner})
	require.NoError(t, err)
	require.Empty(t, opKey.CreatedBy)
	opLink, err := auth.CreateInviteLink(ctx, iam.SystemActor(), o.acme, iam.NewInviteLink{Role: o.owner})
	require.NoError(t, err)
	opInvite, err := auth.CreateAccountInvite(ctx, iam.SystemActor(), iam.NewAccountInvite{Email: "system@credentials.test"})
	require.NoError(t, err)
	require.NoError(t, auth.Ban(ctx, iam.SystemActor(), manager.ID, iam.Ban{}))
	authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Roles = o.changedCatalog }))
	_, err = auth.ResolveAPIKey(ctx, opToken)
	require.NoError(t, err)
	links, err := auth.InviteLinks(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Equal(t, opLink.ID, links.Items[0].ID)
	require.Empty(t, links.Items[0].InvitedBy)
	require.Nil(t, links.Items[0].RevokedAt)
	a := newAPI(t, auth)
	register := func(email, username string) response {
		return a.post("/register", "", map[string]string{"identifier": email, "username": username, "password": authtest.Password, "account_invite_token": opInvite.Code})
	}
	res := register(opInvite.Email, "systeminvitee")
	require.Equal(t, http.StatusAccepted, res.status, "the system's registration invite is live: %s", res)
	res = register("again@credentials.test", "systemagain")
	require.Equal(t, "account_registration_invite_not_found", res.code(), "and single-use: %s", res)

	// Tokens: anything but an exact live key is refused.
	for _, bad := range []string{"", "st_", "st_" + opKey.LookupID, "st_" + opKey.LookupID + "_wrongsecret", "x" + opToken, opToken + "x"} {
		_, err := auth.ResolveAPIKey(ctx, bad)
		require.ErrorIs(t, err, iam.ErrAPIKeyInvalid, bad)
	}
	// ResolveAPIKey reads the wall clock.
	expires := time.Now().Add(time.Second)
	_, expiring, err := auth.MintAPIKey(ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "expiring", Role: o.member, ExpiresAt: &expires})
	require.NoError(t, err)
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	_, err = auth.ResolveAPIKey(ctx, expiring)
	require.ErrorIs(t, err, iam.ErrAPIKeyExpired)
}

func TestCredentialListsPage(t *testing.T) {
	o := newCredentialOrg(t)
	auth, ctx := o.auth, t.Context()
	var keys, links []string
	for i := range 3 {
		k, _, err := auth.MintAPIKey(ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: fmt.Sprintf("key-%d", i), Role: o.member})
		require.NoError(t, err)
		keys = append([]string{k.ID}, keys...)
		l, err := auth.CreateInviteLink(ctx, iam.SystemActor(), o.acme, iam.NewInviteLink{Role: o.member})
		require.NoError(t, err)
		links = append([]string{l.ID}, links...)
	}
	first, err := auth.APIKeys(ctx, o.acme, iam.PageRequest{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, keys[:2], []string{first.Items[0].ID, first.Items[1].ID}, "newest first")
	require.Equal(t, []iam.Perm{o.read}, first.Items[0].Permissions)
	require.NotEmpty(t, first.Next)
	rest, err := auth.APIKeys(ctx, o.acme, iam.PageRequest{Limit: 2, Cursor: first.Next})
	require.NoError(t, err)
	require.Len(t, rest.Items, 1)
	require.Equal(t, keys[2], rest.Items[0].ID)
	require.Empty(t, rest.Next)
	all, err := auth.InviteLinks(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, all.Items, 3)
	require.Equal(t, links[0], all.Items[0].ID)
	require.Empty(t, all.Next)
	page, err := auth.InviteLinks(ctx, o.acme, iam.PageRequest{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, links[0], page.Items[0].ID)
	require.NotEmpty(t, page.Next)
	page, err = auth.InviteLinks(ctx, o.acme, iam.PageRequest{Limit: 1, Cursor: page.Next})
	require.NoError(t, err)
	require.Equal(t, links[1], page.Items[0].ID)
	_, err = auth.APIKeys(ctx, o.acme, iam.PageRequest{Cursor: "not-a-cursor"})
	requireIAMCode(t, err, "invalid_request")
	_, err = auth.APIKeys(ctx, iam.GroupByID(uuid.NewString()), iam.PageRequest{})
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
}
