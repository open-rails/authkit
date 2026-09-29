package securitytest

import (
	"context"
	"net/http"
	"strings"
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
	_, err = h.auth.CreateUser(ctx, iam.SystemActor(), iam.NewUser{Email: unique("impostor") + "@security.test", Username: gone.username})
	require.Error(t, err, "the purged username was released for re-registration")
	_, err = h.auth.User(ctx, iam.UserByUsername(gone.username))
	require.Error(t, err, "the reserved name resolved to a dead account")
	t.Run("control: other names remain available", func(t *testing.T) {
		name := unique("fresh")
		_, err := h.auth.CreateUser(ctx, iam.SystemActor(), iam.NewUser{Email: name + "@security.test", Username: name})
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
		require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{orgOwner.id})))
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
	t.Run("verified flags and imported hashes are the system's", func(t *testing.T) {
		verified := true
		_, err := h.auth.UpdateUser(ctx, iam.UserActor(siteadmin.id), plain.id, iam.UserUpdate{EmailVerified: &verified})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})
	t.Run("control: an actor covering the target", func(t *testing.T) {
		admin := iam.UserActor(siteadmin.id)
		// The target's role needs MFA, so its email stays put (N10).
		require.NoError(t, ops["PatchUserMetadata"](admin, target.id))
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
	_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), holder.id, iam.UserUpdate{Email: &attacker})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeVerificationRequired))
	u, err := h.auth.User(ctx, iam.UserByID(holder.id))
	require.NoError(t, err)
	require.Equal(t, holder.email, u.Email)
	require.True(t, u.EmailVerified)

	t.Run("control: the system vouching for the new address keeps MFA and roles", func(t *testing.T) {
		moved := unique("moved") + "@security.test"
		verified := true
		u, err := h.auth.UpdateUser(ctx, iam.SystemActor(), holder.id, iam.UserUpdate{Email: &moved, EmailVerified: &verified})
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
	_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), id, iam.UserUpdate{EmailVerified: &verified})
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
		_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), a.id, iam.UserUpdate{EmailVerified: &verified})
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
		tok, err := h.auth.MintAccessToken(ctx, iam.SystemActor(), a.id, iam.AccessTokenOptions{SessionID: sid})
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
			require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{Reason: "abuse"}))
			require.NoError(t, h.auth.Unban(ctx, iam.SystemActor(), a.id))
		}},
		{"soft delete", func(a account) {
			require.NoError(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{a.id})))
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

// TestSecurityDeletionRecoveryIsSelfOnly (N5): signing in inside the recovery
// window restores only an account that deleted itself. An account staff
// deleted comes back only through RestoreUsers, with its authority re-checked.
func TestSecurityDeletionRecoveryIsSelfOnly(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	moderator, target := h.newAccount("n5moderator"), h.newAccount("n5target")
	h.grant(iam.RootGroup(), moderator, "moderator")
	resp := h.do(request{method: http.MethodDelete, path: "/admin/users/" + target.id, token: h.login(moderator).AccessToken})
	require.Less(t, resp.status, 300, resp.String())
	login := h.post("/password/login", map[string]string{"identifier": target.email, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, login.status, "an admin-deleted account started its own recovery: %s", login)
	require.Equal(t, "account_disabled", login.errorCode())
	require.NotContains(t, login.String(), "recovery")
	u, err := h.auth.User(ctx, iam.UserByID(target.id), iam.IncludeDeleted())
	require.NoError(t, err)
	require.NotNil(t, u.DeletedAt)

	t.Run("control: a self-deletion is recovered by signing in", func(t *testing.T) {
		self := h.newAccount("n5self")
		resp := h.do(request{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: h.login(self).AccessToken})
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		login := h.post("/password/login", map[string]string{"identifier": self.email, "password": password}, "")
		require.Equal(t, http.StatusConflict, login.status, login.String())
		var body struct {
			Error struct {
				Metadata struct {
					Recovery struct {
						Token string `json:"token"`
					} `json:"recovery"`
				} `json:"metadata"`
			} `json:"error"`
		}
		login.json(t, &body)
		require.NotEmpty(t, body.Error.Metadata.Recovery.Token)
		resp = h.post("/account/recovery/confirm", map[string]string{"token": body.Error.Metadata.Recovery.Token}, "")
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		h.login(self)
	})
}

// TestSecuritySelfRulesUseCanonicalIDs (N6): a differently cased id is the
// same account. It never slips a self-edit, self-ban or self-unban past the
// self rule.
func TestSecuritySelfRulesUseCanonicalIDs(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	staff, other := h.newAccount("n6staff"), h.newAccount("n6other")
	h.grant(iam.RootGroup(), staff, "siteadmin")
	email := unique("n6self") + "@security.test"
	selfOps := map[string]func(a iam.Actor, id string) error{
		"PatchUserMetadata": func(a iam.Actor, id string) error {
			return h.auth.PatchUserMetadata(ctx, a, id, map[string]any{"plan": "enterprise"})
		},
		"UpdateUser": func(a iam.Actor, id string) error {
			_, err := h.auth.UpdateUser(ctx, a, id, iam.UserUpdate{Email: &email})
			return err
		},
		"Ban":   func(a iam.Actor, id string) error { return h.auth.Ban(ctx, a, id, iam.Ban{}) },
		"Unban": func(a iam.Actor, id string) error { return h.auth.Unban(ctx, a, id) },
	}
	upper := strings.ToUpper(staff.id)
	for name, op := range selfOps {
		require.ErrorIs(t, op(iam.UserActor(staff.id), upper), iam.ErrCannotTargetSelf, name+": upper-case target")
		require.ErrorIs(t, op(iam.UserActor(upper), staff.id), iam.ErrCannotTargetSelf, name+": upper-case actor")
	}
	meta, err := h.auth.UserMetadata(ctx, staff.id)
	require.NoError(t, err)
	require.NotContains(t, meta, "plan")
	u, err := h.auth.User(ctx, iam.UserByID(staff.id))
	require.NoError(t, err)
	require.Equal(t, staff.email, u.Email)

	t.Run("control: an upper-case id names another account", func(t *testing.T) {
		require.NoError(t, selfOps["PatchUserMetadata"](iam.UserActor(staff.id), strings.ToUpper(other.id)))
		meta, err := h.auth.UserMetadata(ctx, other.id)
		require.NoError(t, err)
		require.Equal(t, "enterprise", meta["plan"])
	})
}

// TestSecurityContactChangeKeepsEnrolledMFA (N10): a staff email change must
// not leave any account with a second factor unproven, role or not: the next
// reset to the new address would retire that factor and hand the account over.
func TestSecurityContactChangeKeepsEnrolledMFA(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	support, target := h.newAccount("n10support"), h.newAccount("n10target")
	h.grant(iam.RootGroup(), support, "staff")
	h.enrollEmail2FA(target)
	attacker := unique("n10evil") + "@security.test"
	_, err := h.auth.UpdateUser(ctx, iam.UserActor(support.id), target.id, iam.UserUpdate{Email: &attacker})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeVerificationRequired))
	u, err := h.auth.User(ctx, iam.UserByID(target.id))
	require.NoError(t, err)
	require.Equal(t, target.email, u.Email)
	require.True(t, u.EmailVerified)
	var enabled bool
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT enabled FROM profiles.mfa_settings WHERE user_id=$1::uuid`, target.id).Scan(&enabled))
	require.True(t, enabled)

	t.Run("control: an account without a second factor may be moved", func(t *testing.T) {
		plain := h.newAccount("n10plain")
		moved := unique("n10moved") + "@security.test"
		u, err := h.auth.UpdateUser(ctx, iam.UserActor(support.id), plain.id, iam.UserUpdate{Email: &moved})
		require.NoError(t, err)
		require.Equal(t, moved, u.Email)
	})
}

// TestSecurityBannedTokenCreatesNoGroup: a banned account's still-valid access
// token creates no group.
func TestSecurityBannedTokenCreatesNoGroup(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		org := c.Roles.Personas[string(orgPersona)]
		org.Creation = authkit.GroupCreation{Enabled: true}
		c.Roles.Personas[string(orgPersona)] = org
	}))
	ctx := context.Background()
	banned := h.newAccount("bannedcreator")
	token := h.login(banned).AccessToken
	require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), banned.id, iam.Ban{Reason: "abuse"}))
	slug := unique("bannedorg")
	resp := h.post("/"+string(orgPersona), map[string]string{"slug": slug}, token)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	_, err := h.auth.Group(ctx, iam.GroupBySlug(orgPersona, slug))
	require.ErrorIs(t, err, iam.ErrGroupNotFound)

	t.Run("control: a live account creates one", func(t *testing.T) {
		live := h.newAccount("livecreator")
		resp := h.post("/"+string(orgPersona), map[string]string{"slug": unique("liveorg")}, h.login(live).AccessToken)
		require.Equal(t, http.StatusCreated, resp.status, resp.String())
	})
}

// TestSecurityEmailFactorIsPinned (P3, N10): an email factor is bound to the
// address it was proven for. Staff moving the email of an account a verified
// phone keeps proven, then a reset to the new address, never sends the
// account's second-factor codes there.
func TestSecurityEmailFactorIsPinned(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	support, target := h.newAccount("p3support"), h.newAccount("p3target")
	h.grant(iam.RootGroup(), support, "staff")
	h.enrollEmail2FA(target)
	phone, verified := "+1555"+uniqueDigits(7), true
	_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), target.id, iam.UserUpdate{Phone: &phone, PhoneVerified: &verified})
	require.NoError(t, err)

	evil := unique("p3evil") + "@security.test"
	_, err = h.auth.UpdateUser(ctx, iam.UserActor(support.id), target.id, iam.UserUpdate{Email: &evil})
	require.NoError(t, err, "control: the verified phone keeps the account proven")
	require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": evil}, "").status, 300)
	token := h.mail.last(t, `^reset to=`+evil+` .* token=(\S+)`)
	const chosen = "Attacker-chosen-passphrase-3"
	resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": chosen}, "")
	require.Less(t, resp.status, 300, resp.String())

	resp = h.post("/password/login", map[string]string{"identifier": evil, "password": chosen}, "")
	require.Equal(t, http.StatusForbidden, resp.status, "the reset alone signed in an account with a second factor: %s", resp)
	require.Equal(t, "2fa_required", resp.errorCode())
	require.Zero(t, h.mail.count(`^login to=`+evil+` `), "a second-factor code went to the address staff set")
	var pinned *string
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT email FROM profiles.mfa_factors WHERE user_id=$1::uuid AND method='email'`, target.id).Scan(&pinned))
	require.NotNil(t, pinned)
	require.Equal(t, target.email, *pinned)

	t.Run("control: the code at the proven address completes the sign-in", func(t *testing.T) {
		var ch challenge
		resp.json(t, &ch)
		resp := h.post("/2fa/verify", map[string]string{"user_id": target.id, "challenge": ch.Error.Metadata.Challenge,
			"code": h.mail.last(t, `^login to=`+target.email+` code=(\S+)`)}, "")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityStaffDeleteOverridesSelfDelete (P6): a moderator deleting an
// account that already deleted itself records a staff deletion; signing in no
// longer undoes it.
func TestSecurityStaffDeleteOverridesSelfDelete(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	moderator, target := h.newAccount("p6moderator"), h.newAccount("p6target")
	h.grant(iam.RootGroup(), moderator, "moderator")
	// The target deletes itself ahead of moderation.
	resp := h.do(request{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: h.login(target).AccessToken})
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	resp = h.do(request{method: http.MethodDelete, path: "/admin/users/" + target.id, token: h.login(moderator).AccessToken})
	require.Less(t, resp.status, 300, resp.String())
	login := h.post("/password/login", map[string]string{"identifier": target.email, "password": password}, "")
	require.Equal(t, http.StatusUnauthorized, login.status, "signing in undid the moderator's deletion: %s", login)
	require.Equal(t, "account_disabled", login.errorCode())
	require.NotContains(t, login.String(), "recovery")

	t.Run("control: a self-deletion alone stays recoverable", func(t *testing.T) {
		self := h.newAccount("p6self")
		require.NoError(t, opErr(h.auth.DeleteUsers(context.Background(), iam.UserActor(self.id), []string{self.id})))
		login := h.post("/password/login", map[string]string{"identifier": self.email, "password": password}, "")
		require.Equal(t, http.StatusConflict, login.status, login.String())
		require.Equal(t, "account_recovery_required", login.errorCode())
	})
}

// TestSecurityUserManagementNeedsMFA (owner decision c): root:users:manage
// edits other people's accounts, so it needs MFA like root:members:manage.
// Only the system sets another account's password; staff send a reset.
func TestSecurityUserManagementNeedsMFA(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	staff, target := h.newAccount("cstaff"), h.newAccount("ctarget")
	res, err := h.auth.AssignGroupRoles(ctx, iam.SystemActor(), iam.RootGroup(), []iam.Subject{iam.UserSubject(staff.id)}, "staff")
	require.NoError(t, err)
	require.ErrorIs(t, res[0].Err, iam.ErrTwoFAEnrollmentRequired, "a root:users:manage role went to an account without MFA")
	// A role granted while 2FA was off: signing in yields only an enrollment token.
	_, err = h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'staff')`, h.rootGroupID(), staff.id)
	require.NoError(t, err)
	resp := h.post("/password/login", map[string]string{"identifier": staff.email, "password": password}, "")
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.Equal(t, "2fa_enrollment_required", resp.errorCode())

	admin := h.newAccount("cadmin")
	h.grant(iam.RootGroup(), admin, "siteadmin")
	chosen := "Staff-chosen-passphrase-9"
	_, err = h.auth.UpdateUser(ctx, iam.UserActor(admin.id), target.id, iam.UserUpdate{Password: &chosen})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	h.login(target)

	t.Run("control: the system sets it", func(t *testing.T) {
		require.NoError(t, h.setPassword(target.id, chosen))
		resp := h.post("/password/login", map[string]string{"identifier": target.email, "password": chosen}, "")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})
}

// TestSecurityEmailFactorFollowsOwnChange (R3): the account's own email
// change needs MFA and proves the new mailbox, so it moves the email factor
// there; the system's change never does. The factor listing shows where the
// codes go, masked.
func TestSecurityEmailFactorFollowsOwnChange(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	a := h.newAccount("r3owner")
	h.enrollEmail2FA(a)
	token := h.login(a).AccessToken
	pinned := func() string {
		var email string
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT email FROM profiles.mfa_factors WHERE user_id=$1::uuid AND method='email'`, a.id).Scan(&email))
		return email
	}
	listed := func() string {
		resp := h.get("/user/2fa", token)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		var out struct {
			Factors []struct {
				Method string `json:"method"`
				Email  string `json:"email"`
			} `json:"factors"`
		}
		resp.json(t, &out)
		require.Len(t, out.Factors, 1)
		return out.Factors[0].Email
	}
	require.Equal(t, "r***@security.test", listed())

	moved := unique("moved") + "@elsewhere.test"
	resp := h.post("/verify/request", map[string]string{"identifier": moved}, token)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	resp = h.post("/verify/confirm", map[string]string{"identifier": moved, "code": h.verificationCode(moved)}, token)
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	require.Equal(t, moved, pinned(), "the account's own verified change left its codes at the old mailbox")
	require.Equal(t, "m***@elsewhere.test", listed())

	sent := h.mail.count(`^login to=` + a.email + ` `)
	resp = h.post("/password/login", map[string]string{"identifier": moved, "password": password}, "")
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	var ch challenge
	resp.json(t, &ch)
	resp = h.post("/2fa/verify", map[string]string{"user_id": a.id, "challenge": ch.Error.Metadata.Challenge,
		"code": h.mail.last(t, `^login to=`+moved+` code=(\S+)`)}, "")
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	require.Equal(t, sent, h.mail.count(`^login to=`+a.email+` `), "a login code went to the old mailbox")

	t.Run("control: the system change leaves the factor where it was proven", func(t *testing.T) {
		third, verified := unique("third")+"@security.test", true
		_, err := h.auth.UpdateUser(ctx, iam.SystemActor(), a.id, iam.UserUpdate{Email: &third, EmailVerified: &verified})
		require.NoError(t, err)
		require.Equal(t, moved, pinned())
	})
}
