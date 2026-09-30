package apitest_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// The invitations resource over HTTP. A link answers its code once (201); an
// emailed invitation answers 202 whoever holds the address. Both are listed
// and revoked alike (DELETE is idempotent). On root, an email with no role
// invites a registration, which takes root:users:invite.
func TestInvitationRoutes(t *testing.T) {
	o := newCredentialOrg(t)
	auth, ctx := o.auth, t.Context()
	a := newAPI(t, auth)
	manager, member, inviter, holder := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, o.acme, iam.UserSubject(manager.ID), o.manager)
	authtest.GrantRole(t, auth, o.acme, iam.UserSubject(member.ID), o.member)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(inviter.ID), o.inviter)
	managerToken, memberToken := authtest.SignIn(t, auth, manager).AccessToken, authtest.SignIn(t, auth, member).AccessToken
	inviterToken, holderToken := authtest.SignIn(t, auth, inviter).AccessToken, authtest.SignIn(t, auth, holder).AccessToken
	base := "/groups/" + o.acmeID + "/invitations"
	role := o.member.String()

	res := expect(t, http.StatusCreated, a.post(base, managerToken, map[string]any{"role": role}))
	var link iam.InvitationCreated
	res.decode(t, &link)
	require.NotEmpty(t, link.Code)
	require.Nil(t, link.Invitation.Email)
	require.Equal(t, o.member, link.Invitation.Role)

	// The same answer for an address nobody holds and one an account holds;
	// only the email carries the code.
	const newcomer = "newcomer@invitations.test"
	for _, email := range []string{newcomer, holder.Email} {
		res := expect(t, http.StatusAccepted, a.post(base, managerToken, map[string]any{"role": role, "email": email}))
		require.Empty(t, res.body)
	}
	emailed := o.outbox.Last(t, iam.MessageInvite, holder.Email)
	invite, err := url.Parse(emailed.Link)
	require.NoError(t, err)
	carried, err := url.ParseQuery(invite.Fragment)
	require.NoError(t, err)
	require.Len(t, carried, 1, emailed.Link)
	var code string
	for _, values := range carried {
		code = values[0]
	}
	require.NotEmpty(t, code)

	for name, tc := range map[string]struct {
		token  string
		body   map[string]any
		status int
		code   string
	}{
		"a link needs a role":             {managerToken, map[string]any{}, http.StatusBadRequest, "invalid_request"},
		"a role of another persona":       {managerToken, map[string]any{"role": o.inviter.String()}, http.StatusBadRequest, "role_not_assignable"},
		"a bare role name":                {managerToken, map[string]any{"role": "member"}, http.StatusBadRequest, "role_not_assignable"},
		"an address that is not one":      {managerToken, map[string]any{"role": role, "email": "not-an-address"}, http.StatusBadRequest, ""},
		"no role outside root":            {managerToken, map[string]any{"email": "roleless@invitations.test"}, http.StatusBadRequest, "invalid_invite"},
		"a role above the caller's":       {managerToken, map[string]any{"role": o.owner.String()}, http.StatusForbidden, "role_assignment_escalation"},
		"a member lacks members:manage":   {memberToken, map[string]any{"role": role}, http.StatusForbidden, "forbidden"},
		"root authority is not the org's": {inviterToken, map[string]any{"role": role}, http.StatusForbidden, "forbidden"},
	} {
		res := a.post(base, tc.token, tc.body)
		require.Equal(t, tc.status, res.status, "%s: %s", name, res)
		if tc.code != "" {
			require.Equal(t, tc.code, res.code(), name)
		}
	}

	// Both kinds are listed, newest first, never with a code.
	list := func() []iam.Invitation {
		t.Helper()
		res := expect(t, http.StatusOK, a.get(base, managerToken))
		require.NotContains(t, res.String(), link.Code)
		require.NotContains(t, res.String(), code)
		var page iam.ListPage[iam.Invitation]
		res.decode(t, &page)
		return page.Items
	}
	items := list()
	require.Len(t, items, 3)
	var emails []*string
	for _, i := range items {
		emails = append(emails, i.Email)
	}
	holderEmail, newcomerEmail := holder.Email, newcomer
	require.Equal(t, []*string{&holderEmail, &newcomerEmail, nil}, emails)
	require.Equal(t, link.Invitation.ID, items[2].ID)
	expect(t, http.StatusForbidden, a.get(base, memberToken))

	// The account that proved the address redeems its invitation; anyone
	// signed in redeems a link.
	res = expect(t, http.StatusOK, a.post("/invitations/redeem", holderToken, map[string]string{"code": code}))
	var joined iam.Membership
	res.decode(t, &joined)
	require.Equal(t, o.acmeID, joined.Group.ID)
	require.Equal(t, o.member, joined.Role)
	expect(t, http.StatusUnauthorized, a.post("/invitations/redeem", "", map[string]string{"code": link.Code}))
	res = expect(t, http.StatusOK, a.post("/invitations/redeem", inviterToken, map[string]string{"code": link.Code}))
	require.Contains(t, res.String(), `"role":"`+role+`"`)

	// Revoking is idempotent, for either kind, redeemed or unknown.
	for _, id := range []string{items[1].ID, items[1].ID, items[0].ID, link.Invitation.ID, uuid.NewString()} {
		expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: base + "/" + id, token: managerToken}))
	}
	expect(t, http.StatusForbidden, a.do(request{method: http.MethodDelete, path: base + "/" + link.Invitation.ID, token: memberToken}))
	items = list()
	require.NotNil(t, items[1].RevokedAt)
	for _, i := range []int{0, 2} {
		require.NotNil(t, items[i].RedeemedAt)
		require.Nil(t, items[i].RevokedAt, "a redeemed invitation stays redeemed")
	}

	// Root: an email and no role is a registration invite, root:users:invite's
	// to send; a manager of another group sends none.
	root := "/groups/root/invitations"
	const joiner = "joiner@invitations.test"
	expect(t, http.StatusForbidden, a.post(root, managerToken, map[string]any{"email": joiner}))
	expect(t, http.StatusAccepted, a.post(root, inviterToken, map[string]any{"email": joiner}))
	require.NotEmpty(t, o.outbox.Last(t, iam.MessageInvite, joiner).Link)
	res = a.post(root, inviterToken, map[string]any{"role": o.inviter.String()})
	require.Equal(t, http.StatusForbidden, res.status, "a root link takes root:members:manage: %s", res)
	expect(t, http.StatusForbidden, a.get(root, inviterToken))
	roots, err := auth.ListInvitations(ctx, iam.RootGroup(), iam.PageRequest{})
	require.NoError(t, err)
	require.Len(t, roots.Items, 1)
	require.Equal(t, joiner, *roots.Items[0].Email)
	require.True(t, roots.Items[0].Role.IsZero())
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: root + "/" + roots.Items[0].ID, token: inviterToken}))
}
