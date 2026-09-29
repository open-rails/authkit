package securitytest

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/stretchr/testify/require"
)

// TestSecurityPurgedUsernameStaysReserved: purging an account frees its row,
// never its username, so nobody can re-register the name and impersonate the
// purged user to people and links that still know it.
func TestSecurityPurgedUsernameStaysReserved(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	gone := h.newAccount("purged")
	// Final purge is this physical delete, after recovery and host callbacks.
	_, err := h.pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, gone.id)
	require.NoError(t, err)
	_, err = h.auth.CreateUser(ctx, iam.OperatorActor(), iam.NewUser{Email: unique("impostor") + "@security.test", Username: gone.username})
	require.Error(t, err, "the purged username was released for re-registration")
	_, err = h.auth.User(ctx, iam.UserByUsername(gone.username))
	require.Error(t, err, "the reserved name resolved to a dead account")
	t.Run("control: other names remain available", func(t *testing.T) {
		name := unique("fresh")
		_, err := h.auth.CreateUser(ctx, iam.OperatorActor(), iam.NewUser{Email: name + "@security.test", Username: name})
		require.NoError(t, err)
	})
}

// withAccountRoles declares root roles of graded account authority and an
// org persona whose owners hold no root role.
func withAccountRoles(c *authkit.Config) {
	c.Roles = authkit.RoleConfig{
		Personas: map[string]authkit.Persona{
			string(orgPersona):      {Permissions: []string{"org:catalog:read"}},
			string(iam.RootPersona): {Permissions: []string{"root:audit:read"}, RequireMFA: []string{"root:audit:read"}},
		},
		Roles: []authkit.Role{
			{Persona: iam.RootPersona, Name: "staff", Permissions: []string{iam.PermRootUsersManage}},
			{Persona: iam.RootPersona, Name: "moderator", Permissions: []string{iam.PermRootUsersBan, iam.PermRootUsersDelete, iam.PermRootUsersManage}},
			{Persona: iam.RootPersona, Name: "siteadmin", Permissions: []string{"root:users:*", "org:*"}},
			{Persona: iam.RootPersona, Name: "security", Permissions: []string{"root:audit:read"}},
		},
	}
}

func opErr(res []iam.OpResult, err error) error {
	if err != nil {
		return err
	}
	return res[0].Err
}

// accountOps is every account mutation on Auth, by name.
func accountOps(h *host) map[string]func(actor iam.Actor, target string) error {
	ctx := context.Background()
	email := func() *string { v := unique("edited") + "@security.test"; return &v }
	return map[string]func(iam.Actor, string) error{
		"UpdateUser": func(a iam.Actor, id string) error {
			_, err := h.auth.UpdateUser(ctx, a, id, iam.UserUpdate{Email: email()})
			return err
		},
		"PatchUserMetadata": func(a iam.Actor, id string) error {
			return h.auth.PatchUserMetadata(ctx, a, id, map[string]any{"note": "x"})
		},
		"Ban":   func(a iam.Actor, id string) error { return h.auth.Ban(ctx, a, id, iam.Ban{}) },
		"Unban": func(a iam.Actor, id string) error { return h.auth.Unban(ctx, a, id) },
		"DeleteUsers": func(a iam.Actor, id string) error {
			return opErr(h.auth.DeleteUsers(ctx, a, []string{id}))
		},
		"RestoreUsers": func(a iam.Actor, id string) error {
			return opErr(h.auth.RestoreUsers(ctx, a, []string{id}))
		},
		"RevokeAccountSessions": func(a iam.Actor, id string) error {
			_, err := h.auth.RevokeAccountSessions(ctx, a, id)
			return err
		},
		"RevokeSession": func(a iam.Actor, id string) error {
			return h.auth.RevokeSession(ctx, a, id, "0190a0a0-0000-7000-8000-000000000000")
		},
	}
}

// TestSecurityAccountAuthority (H4, M1): an account mutation needs the root
// permission it names AND coverage of the target's grants in root and in every
// group the target holds a role in. A narrow root:users staffer can neither
// edit a more privileged account nor act on a group owner it does not outrank.
func TestSecurityAccountAuthority(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	root := iam.RootGroup()
	staff, moderator := h.newAccount("staff"), h.newAccount("moderator")
	siteadmin, target := h.newAccount("siteadmin"), h.newAccount("admintarget")
	orgOwner, coOwner, plain := h.newAccount("orgowner"), h.newAccount("coowner"), h.newAccount("plain")
	h.grant(root, staff, "staff")
	h.grant(root, moderator, "moderator")
	h.grant(root, siteadmin, "siteadmin")
	h.grant(root, target, "siteadmin")
	group, _ := h.newOrg("acct", orgOwner)
	h.grant(group, coOwner, "owner")
	ops := accountOps(h)

	t.Run("H4: a root:users:manage staffer edits a more privileged account", func(t *testing.T) {
		for _, name := range []string{"UpdateUser", "PatchUserMetadata", "RevokeAccountSessions", "RevokeSession"} {
			require.ErrorIs(t, ops[name](iam.UserActor(staff.id), target.id), iam.ErrAccountAuthorityEscalation, name)
		}
		u, err := h.auth.User(ctx, iam.UserByID(target.id))
		require.NoError(t, err)
		require.Equal(t, target.email, u.Email)
	})
	t.Run("M1: site moderation against a group owner with no root role", func(t *testing.T) {
		for name, op := range ops {
			require.ErrorIs(t, op(iam.UserActor(moderator.id), orgOwner.id), iam.ErrAccountAuthorityEscalation, name)
		}
		resp := h.post("/admin/users/"+orgOwner.id+"/ban", map[string]string{"until": "infinite"}, h.login(moderator).AccessToken)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "account_authority_escalation", resp.errorCode())
	})
	t.Run("M1: restore re-checks the roles the account resumes", func(t *testing.T) {
		require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.OperatorActor(), []string{orgOwner.id})))
		require.ErrorIs(t, ops["RestoreUsers"](iam.UserActor(moderator.id), orgOwner.id), iam.ErrAccountAuthorityEscalation)
		require.NoError(t, ops["RestoreUsers"](iam.UserActor(siteadmin.id), orgOwner.id))
	})
	t.Run("invariant: no root permission, no account authority", func(t *testing.T) {
		for name, op := range ops {
			require.ErrorIs(t, op(iam.UserActor(plain.id), staff.id), iam.ErrInsufficientAuthority, name)
		}
	})
	t.Run("nobody bans, unbans or edits the credentials of their own account", func(t *testing.T) {
		self := iam.UserActor(siteadmin.id)
		require.ErrorIs(t, h.auth.Ban(ctx, self, siteadmin.id, iam.Ban{}), iam.ErrCannotTargetSelf)
		require.ErrorIs(t, h.auth.Unban(ctx, self, siteadmin.id), iam.ErrCannotTargetSelf)
		require.ErrorIs(t, ops["UpdateUser"](self, siteadmin.id), iam.ErrCannotTargetSelf)
	})
	t.Run("verified flags and imported hashes are the operator's", func(t *testing.T) {
		verified := true
		_, err := h.auth.UpdateUser(ctx, iam.UserActor(siteadmin.id), plain.id, iam.UserUpdate{EmailVerified: &verified})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})
	t.Run("control: an actor covering the target", func(t *testing.T) {
		admin := iam.UserActor(siteadmin.id)
		require.NoError(t, ops["UpdateUser"](admin, target.id))
		require.NoError(t, ops["Ban"](admin, coOwner.id))
		require.NoError(t, ops["Unban"](admin, coOwner.id))
		require.NoError(t, ops["UpdateUser"](iam.UserActor(staff.id), plain.id))
		require.NoError(t, ops["RevokeSession"](iam.UserActor(plain.id), plain.id), "an account revokes its own sessions")
	})
}

// TestSecurityContactChangeKeepsMFARoles (H4): an email change must not leave
// an account holding MFA-required roles with no proven contact, since the next
// proof (a password reset to the new address) retires its second factor.
func TestSecurityContactChangeKeepsMFARoles(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	holder := h.newAccount("mfaholder")
	h.enrollEmail2FA(holder)
	h.grant(iam.RootGroup(), holder, "security")
	attacker := unique("takeover") + "@security.test"
	_, err := h.auth.UpdateUser(ctx, iam.OperatorActor(), holder.id, iam.UserUpdate{Email: &attacker})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeVerificationRequired))
	u, err := h.auth.User(ctx, iam.UserByID(holder.id))
	require.NoError(t, err)
	require.Equal(t, holder.email, u.Email)
	require.True(t, u.EmailVerified)

	t.Run("control: an operator vouching for the new address keeps MFA and roles", func(t *testing.T) {
		moved := unique("moved") + "@security.test"
		verified := true
		u, err := h.auth.UpdateUser(ctx, iam.OperatorActor(), holder.id, iam.UserUpdate{Email: &moved, EmailVerified: &verified})
		require.NoError(t, err)
		require.Equal(t, moved, u.Email)
		var enabled bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT enabled FROM profiles.mfa_settings WHERE user_id=$1::uuid`, holder.id).Scan(&enabled))
		require.True(t, enabled)
		roles, err := h.auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(holder.id)})
		require.NoError(t, err)
		require.Equal(t, iam.Role("security"), roles[iam.UserSubject(holder.id)])
	})
}

// TestSecurityVerifiedOnlyByProof (L8): a host cannot mark a contact verified
// without the proof transition. Verifying an address a squatter registered
// retires the squatter's password and sessions.
func TestSecurityVerifiedOnlyByProof(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	victim := unique("victim") + "@security.test"
	squatter := h.register(victim)
	id := h.userID(victim)
	verified := true
	_, err := h.auth.UpdateUser(ctx, iam.OperatorActor(), id, iam.UserUpdate{EmailVerified: &verified})
	require.NoError(t, err)
	login := h.post("/password/login", map[string]string{"identifier": victim, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, login.status, "the squatter's password survived: %s", login)
	require.Equal(t, http.StatusUnauthorized, h.refresh(squatter.RefreshToken).status, "the squatter's session survived")
	u, err := h.auth.User(ctx, iam.UserByID(id))
	require.NoError(t, err)
	require.True(t, u.EmailVerified)

	t.Run("control: verifying a proven account keeps its credentials", func(t *testing.T) {
		a := h.newAccount("proven")
		s := h.login(a)
		_, err := h.auth.UpdateUser(ctx, iam.OperatorActor(), a.id, iam.UserUpdate{EmailVerified: &verified})
		require.NoError(t, err)
		h.login(a)
		require.Equal(t, http.StatusOK, h.refresh(s.RefreshToken).status)
	})
}

// TestSecurityInlinePasswordNeedsSecondFactor (M5): for an account with a
// second factor, a password typed into a sensitive request never stands in
// for a fresh step-up with that factor.
func TestSecurityInlinePasswordNeedsSecondFactor(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	stale := func(a account, access string) string {
		_, claims := splitToken(t, access)
		sid, _ := claims["sid"].(string)
		require.NotEmpty(t, sid)
		// A stolen session whose authentication is old: the password branch
		// of the fresh-auth gate is the only way through.
		_, err := h.pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET created_at=now()-interval '1 day', last_authenticated_at=now()-interval '1 day', mfa_authenticated_at=now()-interval '1 day' WHERE id=$1::uuid`, sid)
		require.NoError(t, err)
		tok, err := h.auth.MintAccessToken(ctx, iam.OperatorActor(), a.id, iam.AccessTokenOptions{SessionID: sid})
		require.NoError(t, err)
		return tok.Value
	}
	a := h.newAccount("mfastep")
	h.enrollEmail2FA(a)
	ch := h.passwordStep(a, "198.51.100.9")
	resp := h.secondStep(a, ch, h.mail.last(t, `^login to=`+a.email+` code=(\S+)`), "198.51.100.9")
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	token := stale(a, session(t, resp).AccessToken)
	for _, req := range []request{
		{method: http.MethodPost, path: "/verify/request", body: map[string]string{"identifier": unique("evil") + "@security.test", "password": password}},
		{method: http.MethodPost, path: "/user/password", body: map[string]string{"current_password": password, "new_password": password + "x"}},
		{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}},
	} {
		req.token = token
		resp := h.do(req)
		require.Equal(t, http.StatusForbidden, resp.status, "%s %s: %s", req.method, req.path, resp)
		require.Equal(t, "step_up_required", resp.errorCode())
	}
	u, err := h.auth.User(ctx, iam.UserByID(a.id))
	require.NoError(t, err)
	require.Equal(t, a.email, u.Email)

	t.Run("control: a password clears the gate without a second factor", func(t *testing.T) {
		b := h.newAccount("pwdstep")
		resp := h.do(request{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: stale(b, h.login(b).AccessToken)})
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	})
}

// TestSecurityAccountLifecycleRevokesCredentials (H1): banning or deleting an
// account revokes the API keys and invite links it issued, and lifting the
// ban does not bring them back.
func TestSecurityAccountLifecycleRevokesCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	founder := h.newAccount("h1founder")
	group, base := h.newOrg("h1", founder)
	founderKey := h.issue(base+"/api-keys", h.login(founder).AccessToken, map[string]any{"name": "founder-key", "role": "owner"})
	for _, tc := range []struct {
		name string
		end  func(a account)
	}{
		{"ban", func(a account) {
			require.NoError(t, h.auth.Ban(ctx, iam.OperatorActor(), a.id, iam.Ban{Reason: "abuse"}))
			require.NoError(t, h.auth.Unban(ctx, iam.OperatorActor(), a.id))
		}},
		{"soft delete", func(a account) {
			require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.OperatorActor(), []string{a.id})))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator := h.newAccount("h1creator")
			h.grant(group, creator, "owner")
			token := h.login(creator).AccessToken
			link := h.issue(base+"/invites/links", token, map[string]any{"role": "owner"})
			key := h.issue(base+"/api-keys", token, map[string]any{"name": unique("key"), "role": "owner"})
			tc.end(creator)
			require.False(t, liveKey(t, h, group, key.ID))
			require.False(t, liveLink(t, h, group, link.ID))
			fresh := h.newAccount("h1fresh")
			resp := h.post("/invites/redeem", map[string]string{"code": link.Code}, h.login(fresh).AccessToken)
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			can, err := h.auth.Can(ctx, iam.UserActor(fresh.id), group, iam.PermSelfDelete(orgPersona))
			require.NoError(t, err)
			require.False(t, can)
		})
	}
	t.Run("control: other issuers' credentials survive", func(t *testing.T) {
		require.True(t, liveKey(t, h, group, founderKey.ID))
	})
}
