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
	key, token, err := createKey(auth, ctx, mgr, o.acme, iam.NewAPIKey{Name: " ci ", Role: o.member})
	require.NoError(t, err)
	require.Equal(t, iam.APIKey{ID: key.ID, LookupID: key.LookupID, GroupID: o.acmeID, Name: "ci", Role: o.member, Permissions: []iam.Perm{o.read}, CreatedBy: &manager.ID, CreatedAt: key.CreatedAt}, key)
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
	link, err := auth.CreateInvitation(ctx, mgr, o.acme, iam.NewInvitation{Role: o.member})
	require.NoError(t, err)
	require.NotEmpty(t, link.Code)

	// No escalation, and no capability means no issuance.
	_, _, err = createKey(auth, ctx, mgr, o.acme, iam.NewAPIKey{Name: "owner", Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = auth.CreateInvitation(ctx, mgr, o.acme, iam.NewInvitation{Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, _, err = createKey(auth, ctx, iam.UserActor(member.ID), o.acme, iam.NewAPIKey{Name: "member", Role: o.member})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	var nobody iam.Role
	require.NoError(t, nobody.UnmarshalText([]byte("org:nobody")))
	_, _, err = createKey(auth, ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "unknown", Role: nobody})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "the system skips authority, never role validity")

	// Machine actors never issue credentials, whatever authority they hold.
	managerKey, _, err := createKey(auth, ctx, iam.UserActor(o.founder.ID), o.acme, iam.NewAPIKey{Name: "manager-key", Role: o.manager})
	require.NoError(t, err)
	for name, a := range map[string]iam.Actor{
		"zero":               {},
		"api_key":            iam.APIKeyActor(managerKey.ID),
		"remote_application": iam.RemoteApplicationActor(uuid.NewString()),
		"delegated":          iam.DelegatedActor(iam.DelegatedGrant{Issuer: authtest.Issuer, Subject: manager.ID, Permissions: []iam.Perm{o.member.Persona().OwnerGrant()}}),
	} {
		_, _, err := createKey(auth, ctx, a, o.acme, iam.NewAPIKey{Name: name, Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
		_, err = auth.CreateInvitation(ctx, a, o.acme, iam.NewInvitation{Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
		_, err = auth.CreateInvitation(ctx, a, o.acme, iam.NewInvitation{Email: name + "@machine.test", Role: o.member})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, name)
	}

	// Revoking needs the authority to issue, from any actor kind.
	require.ErrorIs(t, auth.RevokeAPIKey(ctx, iam.UserActor(member.ID), o.acme, key.ID), iam.ErrInsufficientAuthority)
	require.NoError(t, auth.RevokeAPIKey(ctx, iam.APIKeyActor(managerKey.ID), o.acme, key.ID))
	_, err = auth.ResolveAPIKey(ctx, token)
	require.ErrorIs(t, err, iam.ErrAPIKeyRevoked)
	require.NoError(t, auth.RevokeAPIKey(ctx, mgr, o.acme, key.ID), "revoking a revoked key is a no-op")
	require.ErrorIs(t, auth.RevokeAPIKey(ctx, mgr, o.acme, uuid.NewString()), iam.ErrAPIKeyNotFound)
	require.ErrorIs(t, auth.RevokeAPIKey(ctx, mgr, iam.RootGroup(), key.ID), iam.ErrAPIKeyNotFound, "another group's key is unknown here")
	require.ErrorIs(t, auth.RevokeInvitation(ctx, iam.UserActor(member.ID), o.acme, link.Invitation.ID), iam.ErrInsufficientAuthority)
	require.NoError(t, auth.RevokeInvitation(ctx, mgr, o.acme, link.Invitation.ID))
	require.NoError(t, auth.RevokeInvitation(ctx, mgr, o.acme, link.Invitation.ID), "revoking a revoked invitation is a no-op")
	require.ErrorIs(t, auth.RevokeInvitation(ctx, mgr, o.acme, uuid.NewString()), iam.ErrInvitationNotFound)

	// Registration invites: plain needs root:users:invite, a role-carrying one
	// the group's members:manage and coverage of the role.
	_, err = auth.CreateInvitation(ctx, mgr, iam.RootGroup(), iam.NewInvitation{Email: "plain@credentials.test"})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = auth.CreateInvitation(ctx, iam.UserActor(inviter.ID), iam.RootGroup(), iam.NewInvitation{Email: "plain@credentials.test"})
	require.NoError(t, err)
	_, err = auth.CreateInvitation(ctx, iam.UserActor(inviter.ID), o.acme, iam.NewInvitation{Email: "join@credentials.test", Role: o.member})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	_, err = auth.CreateInvitation(ctx, mgr, o.acme, iam.NewInvitation{Email: "join@credentials.test", Role: o.owner})
	require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
	_, err = auth.CreateInvitation(ctx, mgr, o.acme, iam.NewInvitation{Email: "join@credentials.test"})
	requireIAMCode(t, err, "invalid_invite") // an invitation without a role is root's

	// The system issues with no creator, and no sweep takes its credentials:
	// not a creator's (a ban) nor the whole site's (a changed root catalog at
	// boot).
	opKey, opToken, err := createKey(auth, ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "system", Role: o.owner})
	require.NoError(t, err)
	require.Empty(t, opKey.CreatedBy)
	opLink, err := auth.CreateInvitation(ctx, iam.SystemActor(), o.acme, iam.NewInvitation{Role: o.owner})
	require.NoError(t, err)
	opInvite, err := auth.CreateInvitation(ctx, iam.SystemActor(), iam.RootGroup(), iam.NewInvitation{Email: "system@credentials.test"})
	require.NoError(t, err)
	require.NoError(t, auth.Ban(ctx, iam.SystemActor(), manager.ID, iam.Ban{}))
	authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Roles = o.changedCatalog }))
	_, err = auth.ResolveAPIKey(ctx, opToken)
	require.NoError(t, err)
	links, err := auth.ListInvitations(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Equal(t, opLink.Invitation.ID, links.Items[0].ID)
	require.Empty(t, links.Items[0].CreatedBy)
	require.Nil(t, links.Items[0].RevokedAt)
	a := newAPI(t, auth)
	register := func(email, username string) response {
		return a.post("/register", "", map[string]string{"identifier": email, "username": username, "password": authtest.Password, "account_invite_token": opInvite.Code})
	}
	res := register(*opInvite.Invitation.Email, "systeminvitee")
	require.Equal(t, http.StatusAccepted, res.status, "the system's registration invite is live: %s", res)
	res = register("again@credentials.test", "systemagain")
	require.Equal(t, "invitation_not_found", res.code(), "and single-use: %s", res)

	// Tokens: anything but an exact live key is refused.
	for _, bad := range []string{"", "st_", "st_" + opKey.LookupID, "st_" + opKey.LookupID + "_wrongsecret", "x" + opToken, opToken + "x"} {
		_, err := auth.ResolveAPIKey(ctx, bad)
		require.ErrorIs(t, err, iam.ErrAPIKeyInvalid, bad)
	}
	// ResolveAPIKey reads the wall clock.
	expires := time.Now().Add(time.Second)
	_, expiring, err := createKey(auth, ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: "expiring", Role: o.member, ExpiresAt: &expires})
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
		k, _, err := createKey(auth, ctx, iam.SystemActor(), o.acme, iam.NewAPIKey{Name: fmt.Sprintf("key-%d", i), Role: o.member})
		require.NoError(t, err)
		keys = append([]string{k.ID}, keys...)
		l, err := auth.CreateInvitation(ctx, iam.SystemActor(), o.acme, iam.NewInvitation{Role: o.member})
		require.NoError(t, err)
		links = append([]string{l.Invitation.ID}, links...)
	}
	first, err := auth.ListAPIKeys(ctx, o.acme, iam.PageRequest{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, keys[:2], []string{first.Items[0].ID, first.Items[1].ID}, "newest first")
	require.Equal(t, []iam.Perm{o.read}, first.Items[0].Permissions)
	require.NotEmpty(t, first.Next)
	rest, err := auth.ListAPIKeys(ctx, o.acme, iam.PageRequest{Limit: 2, Cursor: first.Next})
	require.NoError(t, err)
	require.Len(t, rest.Items, 1)
	require.Equal(t, keys[2], rest.Items[0].ID)
	require.Empty(t, rest.Next)
	all, err := auth.ListInvitations(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, all.Items, 3)
	require.Equal(t, links[0], all.Items[0].ID)
	require.Empty(t, all.Next)
	page, err := auth.ListInvitations(ctx, o.acme, iam.PageRequest{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, links[0], page.Items[0].ID)
	require.NotEmpty(t, page.Next)
	page, err = auth.ListInvitations(ctx, o.acme, iam.PageRequest{Limit: 1, Cursor: page.Next})
	require.NoError(t, err)
	require.Equal(t, links[1], page.Items[0].ID)
	_, err = auth.ListAPIKeys(ctx, o.acme, iam.PageRequest{Cursor: "not-a-cursor"})
	requireIAMCode(t, err, "invalid_request")
	_, err = auth.ListAPIKeys(ctx, iam.GroupByID(uuid.NewString()), iam.PageRequest{})
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
}

// Links and email invitations are one resource: created, listed and revoked
// through one set of operations, the plain email invitation in root.
func TestInvitationsAreOneResource(t *testing.T) {
	o := newCredentialOrg(t)
	auth, ctx := o.auth, t.Context()
	founder := iam.UserActor(o.founder.ID)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	link, err := auth.CreateInvitation(ctx, founder, o.acme, iam.NewInvitation{Role: o.member, ExpiresAt: &expires})
	require.NoError(t, err)
	require.NotEmpty(t, link.Code)
	require.Contains(t, link.URL, link.Code)
	require.Equal(t, iam.Invitation{ID: link.Invitation.ID, GroupID: o.acmeID, Role: o.member, CreatedBy: &o.founder.ID,
		CreatedAt: link.Invitation.CreatedAt, ExpiresAt: link.Invitation.ExpiresAt}, link.Invitation)
	require.True(t, expires.Equal(*link.Invitation.ExpiresAt))
	emailed, err := auth.CreateInvitation(ctx, founder, o.acme, iam.NewInvitation{Email: "Joiner@Example.test", Role: o.member})
	require.NoError(t, err)
	require.Equal(t, "joiner@example.test", *emailed.Invitation.Email)
	require.WithinDuration(t, time.Now().Add(7*24*time.Hour), *emailed.Invitation.ExpiresAt, time.Minute, "an email invitation lives 7 days by default")
	far := time.Now().Add(90 * 24 * time.Hour)
	capped, err := auth.CreateInvitation(ctx, founder, o.acme, iam.NewInvitation{Role: o.member, ExpiresAt: &far})
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().Add(30*24*time.Hour), *capped.Invitation.ExpiresAt, time.Minute, "a link lives at most 30 days")
	past := time.Now().Add(-time.Minute)
	_, err = auth.CreateInvitation(ctx, founder, o.acme, iam.NewInvitation{Role: o.member, ExpiresAt: &past})
	requireIAMCode(t, err, "invalid_expiry")
	plain, err := auth.CreateInvitation(ctx, iam.SystemActor(), iam.RootGroup(), iam.NewInvitation{Email: "newcomer@example.test"})
	require.NoError(t, err)

	list, err := auth.ListInvitations(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	var ids, emails []string
	for _, i := range list.Items {
		ids, emails = append(ids, i.ID), append(emails, *i.Email)
	}
	require.Equal(t, []string{capped.Invitation.ID, emailed.Invitation.ID, link.Invitation.ID}, ids, "newest first, both kinds")
	require.Equal(t, []string{"", "joiner@example.test", ""}, emails)
	roots, err := auth.ListInvitations(ctx, iam.RootGroup(), iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, roots.Items, 1)
	require.Equal(t, plain.Invitation.ID, roots.Items[0].ID)
	require.True(t, roots.Items[0].Role.IsZero(), "a plain invitation carries no role")

	require.NoError(t, auth.RevokeInvitation(ctx, founder, o.acme, emailed.Invitation.ID))
	require.NoError(t, auth.RevokeInvitation(ctx, founder, o.acme, emailed.Invitation.ID), "revoking twice is a no-op")
	require.ErrorIs(t, auth.RevokeInvitation(ctx, founder, iam.RootGroup(), link.Invitation.ID), iam.ErrInvitationNotFound, "another group's invitation")
	require.ErrorIs(t, auth.RevokeInvitation(ctx, founder, iam.RootGroup(), plain.Invitation.ID), iam.ErrInsufficientAuthority, "a plain invitation needs root:users:invite")
	require.NoError(t, auth.RevokeInvitation(ctx, iam.SystemActor(), iam.RootGroup(), plain.Invitation.ID))
	list, err = auth.ListInvitations(ctx, o.acme, iam.PageRequest{})
	require.NoError(t, err)
	require.NotNil(t, list.Items[1].RevokedAt)
	require.Nil(t, list.Items[0].RevokedAt)
}
