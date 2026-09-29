package securitytest

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestSecurityDeadCreatorCredentials (H1): banning or deleting an account ends
// its API keys on the host's own routes and its invite links at once; the
// credentials never outlive the account that issued them.
func TestSecurityDeadCreatorCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		c.Roles.Roles = append(c.Roles.Roles, authkit.Role{Persona: iam.RootPersona, Name: "staff", Permissions: append(iam.IntrinsicRootPermissions(), "org:*")})
	}))
	staff, founder := h.newAccount("staff"), h.newAccount("founder")
	h.grant(iam.RootGroup(), staff, "staff")
	staffToken := h.login(staff).AccessToken
	group, base := h.newOrg("h1", founder)
	gate := h.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	hostRoute := func(token string) int {
		r := httptest.NewRequest(http.MethodGet, "https://host.security.test/orders", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w.Code
	}
	for _, end := range []struct {
		name string
		req  func(id string) request
	}{
		{"ban", func(id string) request {
			return request{method: http.MethodPost, path: "/admin/users/" + id + "/ban", body: map[string]any{"until": "infinite", "reason": "spam"}, token: staffToken}
		}},
		{"delete", func(id string) request {
			return request{method: http.MethodDelete, path: "/admin/users/" + id, token: staffToken}
		}},
	} {
		t.Run(end.name, func(t *testing.T) {
			creator := h.newAccount("creator")
			h.grant(group, creator, "manager")
			token := h.login(creator).AccessToken
			key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "member"})
			link := h.issue(base+"/invites/links", token, map[string]any{"role": "member"})
			require.Equal(t, http.StatusNoContent, hostRoute(key.Secret), "control: the key works while its creator is live")

			resp := h.do(end.req(creator.id))
			require.Less(t, resp.status, 300, resp.String())
			require.Equal(t, http.StatusUnauthorized, hostRoute(key.Secret))
			stranger := h.newAccount("stranger")
			resp = h.post("/invites/redeem", map[string]string{"code": link.Code}, h.login(stranger).AccessToken)
			require.GreaterOrEqual(t, resp.status, 400, resp.String())
			roles, err := h.auth.GroupRoles(context.Background(), group, []iam.Subject{iam.UserSubject(stranger.id)})
			require.NoError(t, err)
			require.Empty(t, roles, "a dead creator's link admitted a stranger")
		})
	}
}

// TestSecurityFirstProofRevokesSquatterInvitations (N4): an account holding an
// address nobody proved may be handed a role by user id. When the real owner
// proves the address, the invite links and account invitations the squatter
// minted with that role die with the squatter's other credentials.
func TestSecurityFirstProofRevokesSquatterInvitations(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	founder := h.newAccount("n4founder")
	group, base := h.newOrg("n4", founder)
	victim := unique("newhire") + "@security.test"
	squatter := h.register(victim)
	squatterID := h.userID(victim)
	h.grant(group, account{id: squatterID}, "manager")
	link := h.issue(base+"/invites/links", squatter.AccessToken, map[string]any{"role": "member"})
	resp := h.post(base+"/members", map[string]string{"email": unique("sockpuppet") + "@security.test", "role": "member"}, squatter.AccessToken)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	require.True(t, liveLink(t, h, group, link.ID), "control: the squatter's link is live before the proof")

	h.proveEmail(victim, "Owner-proves-the-address-1")
	require.False(t, liveLink(t, h, group, link.ID), "the squatter's link survived the owner's proof")
	var live int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.account_registration_invites WHERE invited_by=$1::uuid AND revoked_at IS NULL`, squatterID).Scan(&live))
	require.Zero(t, live, "the squatter's account invitation survived the owner's proof")
	sockpuppet := h.newAccount("sockpuppet")
	resp = h.post("/invites/redeem", map[string]string{"code": link.Code}, h.login(sockpuppet).AccessToken)
	require.Equal(t, http.StatusBadRequest, resp.status, resp.String())
	roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.UserSubject(sockpuppet.id)})
	require.NoError(t, err)
	require.Empty(t, roles, "the squatter's link admitted its sockpuppet")
}

// TestSecurityMFARequirementRevokesMachineCredentials (N8): an API key or an
// application can present no second factor. When the host makes a permission
// need MFA, the keys and application roles reaching it are revoked at the next
// boot and confer nothing even before.
func TestSecurityMFARequirementRevokesMachineCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("n8owner")
	group, base := h.newOrg("n8", owner)
	token := h.login(owner).AccessToken
	key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "member"})
	s := newSigner(t, "n8-app")
	const appIssuer = "https://n8-app.security.test"
	resp := h.post(base+"/remote-applications", map[string]any{"slug": "n8-app", "issuer": appIssuer,
		"public_keys": []map[string]string{{"kid": s.KID(), "public_key_pem": pemOf(t, s.PublicKey())}}}, token)
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	resp = h.do(request{method: http.MethodPut, path: base + "/remote-applications/n8-app/roles/member", token: token})
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	app, err := h.auth.RemoteApplication(ctx, appIssuer)
	require.NoError(t, err)
	hostRoute := func(auth *authkit.Auth, bearer string) int {
		gate := auth.RequirePermission(group, "org:catalog:read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		r := httptest.NewRequest(http.MethodGet, "https://host.security.test/catalog", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusNoContent, hostRoute(h.auth, key.Secret), "control: the key works")
	require.Equal(t, http.StatusNoContent, hostRoute(h.auth, appToken(t, s, appIssuer)), "control: the application works")

	// The host redeploys with org:catalog:read needing MFA.
	cfg := h.cfg.engine
	personas := maps.Clone(cfg.Roles.Personas)
	org := personas[string(orgPersona)]
	org.RequireMFA = []string{"org:catalog:read"}
	personas[string(orgPersona)] = org
	cfg.Roles.Personas = personas
	rebooted, err := authkit.New(ctx, cfg, h.cfg.deps)
	require.NoError(t, err)
	t.Cleanup(rebooted.Close)

	require.Equal(t, http.StatusUnauthorized, hostRoute(rebooted, key.Secret))
	require.False(t, liveKey(t, h, group, key.ID), "the boot sweep kept an API key whose role needs MFA")
	roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)})
	require.NoError(t, err)
	require.Empty(t, roles, "the boot sweep kept an application role that needs MFA")
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, hostRoute(rebooted, appToken(t, s, appIssuer)))
}

// TestSecurityAPIKeysNeedPersonaOptIn: a persona without APIKeys has no keys,
// minted by a user or the system.
func TestSecurityAPIKeysNeedPersonaOptIn(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	owner := h.newAccount("nokeysowner")
	group, _ := h.newOrg("nokeys", owner)
	for _, a := range []iam.Actor{iam.UserActor(owner.id), iam.SystemActor()} {
		_, _, err := h.auth.MintAPIKey(ctx, a, group, iam.NewAPIKey{Name: "ci", Role: iam.OwnerRole})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, a.String())
	}
	keys, err := h.auth.APIKeys(ctx, group, iam.PageRequest{})
	require.NoError(t, err)
	require.Empty(t, keys.Items)
}

// registerApp registers a group application with token and gives it role.
func (h *host) registerApp(base, token, slug string, role iam.Role) iam.RemoteApplication {
	h.t.Helper()
	iss := "https://" + slug + ".security.test"
	resp := h.post(base+"/remote-applications", map[string]any{"slug": slug, "issuer": iss,
		"public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(h.t)}}}, token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
	resp = h.do(request{method: http.MethodPut, path: base + "/remote-applications/" + slug + "/roles/" + string(role), token: token})
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	app, err := h.auth.RemoteApplication(context.Background(), iss)
	require.NoError(h.t, err)
	return app
}

func (h *host) roleOf(group iam.GroupRef, subject iam.Subject) iam.Role {
	h.t.Helper()
	roles, err := h.auth.GroupRoles(context.Background(), group, []iam.Subject{subject})
	require.NoError(h.t, err)
	return roles[subject]
}

// reboot starts AuthKit again on the host's database with cfg.
func (h *host) reboot(cfg authkit.Config) {
	h.t.Helper()
	runtime, err := authkit.New(context.Background(), cfg, h.cfg.deps)
	require.NoError(h.t, err, "a credential sweep refused the boot")
	h.t.Cleanup(runtime.Close)
}

// TestSecurityCredentialSweepNeverBlocksBoot (P2): an application owner role
// that already confers nothing (it needs MFA, or its registrar is gone) is
// retired without the last-owner refusal, and the boot sweep never refuses:
// it retires and logs. No stored state keeps AuthKit from starting or blocks
// a root custom-role edit.
func TestSecurityCredentialSweepNeverBlocksBoot(t *testing.T) {
	ctx := context.Background()
	t.Run("RequireMFA added to a permission an application owner holds", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2aowner")
		group, base := h.newOrg("p2a", owner)
		app := h.registerApp(base, h.login(owner).AccessToken, "p2a-app", iam.OwnerRole)
		cfg := h.cfg.engine
		personas := maps.Clone(cfg.Roles.Personas)
		org := personas[string(orgPersona)]
		org.RequireMFA = []string{"org:catalog:read"}
		personas[string(orgPersona)] = org
		cfg.Roles.Personas = personas
		h.reboot(cfg)
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)), "the application kept an owner role that needs MFA")
		require.Equal(t, iam.OwnerRole, h.roleOf(group, iam.UserSubject(owner.id)))
	})
	t.Run("2FA turned on with an application holding root owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withApps), withEngine(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
		s := newSigner(t, "p2b-kid")
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
			Slug: "p2b-app", Issuer: "https://p2b-app.security.test", PublicKeys: staticKeys(t, s), Enabled: true,
		})
		require.NoError(t, err)
		grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), iam.OwnerRole)
		cfg := h.cfg.engine
		cfg.TwoFactor.Mode = iam.TwoFactorOptional
		h.reboot(cfg)
		require.Empty(t, h.roleOf(iam.RootGroup(), iam.RemoteApplicationSubject(app.ID)))
	})
	t.Run("a pre-0008 group registration as its group's only owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2cowner")
		group, base := h.newOrg("p2c", owner)
		app := h.registerApp(base, h.login(owner).AccessToken, "p2c-app", iam.OwnerRole)
		// The rows a pre-0008 deployment left: no registrar, and the
		// application is the group's only owner.
		_, err := h.pool.Exec(ctx, `UPDATE profiles.remote_applications SET registered_by=NULL WHERE id=$1::uuid`, app.ID)
		require.NoError(t, err)
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.group_user_roles WHERE user_id=$1::uuid`, owner.id)
		require.NoError(t, err)
		// The first boot after the upgrade sweeps: the fingerprint changed.
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.role_catalog_state`)
		require.NoError(t, err)
		h.reboot(h.cfg.engine)
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
	})
	t.Run("Required 2FA: an application orphaned by its registrar's first proof", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
			c.TwoFactor.Mode = iam.TwoFactorRequired
			c.Roles.Personas[string(iam.RootPersona)] = authkit.Persona{CustomRoles: true}
		}))
		// An account whose address nobody proved founds a group and makes its
		// own application an owner, then proves the address.
		name := unique("p2dfounder")
		email := name + "@security.test"
		u, err := h.auth.CreateUser(ctx, iam.SystemActor(), iam.NewUser{Email: email, Username: name, Password: password})
		require.NoError(t, err)
		group := iam.GroupBySlug(orgPersona, unique("p2d"))
		_, err = h.createOrg(ctx, group, account{id: u.ID})
		require.NoError(t, err)
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.UserActor(u.ID), group, iam.RemoteApplication{
			Slug: "p2d-app", Issuer: "https://p2d-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "p2d-kid")), Enabled: true,
		})
		require.NoError(t, err)
		require.NoError(t, opErr(h.auth.AssignGroupRoles(ctx, iam.UserActor(u.ID), group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, iam.OwnerRole)))
		require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": email}, "").status, 300)
		token := h.mail.last(t, `^reset to=`+email+` .* token=(\S+)`)
		resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": "Founder-proves-the-address-4"}, "")
		require.Less(t, resp.status, 300, resp.String())
		var orphaned bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT registered_by IS NULL FROM profiles.remote_applications WHERE id=$1::uuid`, app.ID).Scan(&orphaned))
		require.True(t, orphaned, "control: the first proof orphans the application")

		// A root custom-role edit sweeps the whole site.
		require.NoError(t, h.auth.DefineGroupRole(ctx, iam.SystemActor(), iam.RootGroup(), iam.CustomRole{Name: "auditor", Permissions: []string{iam.PermRootUsersRead}}))
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
		require.Equal(t, iam.OwnerRole, h.roleOf(group, iam.UserSubject(u.ID)))
	})
	t.Run("control: a live registrar's chosen change still keeps the last owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2eowner")
		_, base := h.newOrg("p2e", owner)
		token := h.login(owner).AccessToken
		h.registerApp(base, token, "p2e-app", iam.OwnerRole)
		resp := h.do(request{method: http.MethodDelete, path: base + "/members/" + owner.id, token: token})
		require.Equal(t, http.StatusConflict, resp.status, resp.String())
		require.Equal(t, "last_owner", resp.errorCode())
	})
}
