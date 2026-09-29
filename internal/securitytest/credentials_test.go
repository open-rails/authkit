package securitytest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/stretchr/testify/require"
)

// TestSecurityDeadCreatorCredentials (H1): banning or deleting an account ends
// its API keys on the host's own routes and its invite links at once; the
// credentials never outlive the account that issued them.
func TestSecurityDeadCreatorCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		c.Roles.Root.Role("staff", c.Roles.Root.Users.All(), orgPersona.OwnerGrant())
	}))
	staff, founder := h.newAccount("staff"), h.newAccount("founder")
	h.grant(iam.RootGroup(), staff, "staff")
	staffToken := h.login(staff).AccessToken
	group, base := h.newOrg(founder)
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
	group, base := h.newOrg(founder)
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
	group, base := h.newOrg(owner)
	token := h.login(owner).AccessToken
	key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "member"})
	s := newSigner(t, "n8-app")
	const appIssuer = "https://n8-app.security.test"
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.UserActor(owner.id), group, iam.RemoteApplication{
		Slug: "n8-app", Issuer: appIssuer, PublicKeys: staticKeys(t, s), Enabled: true,
	})
	require.NoError(t, err)
	require.NoError(t, opErr(h.auth.AssignGroupRoles(ctx, iam.UserActor(owner.id), group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, roleIn(t, h.auth, group, "member"))))
	hostRoute := func(auth *authkit.Client, bearer string) int {
		gate := auth.RequirePermissionOn(group, ident.Perm("org:catalog:read"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
	m := newSecurityModel()
	m.org.RequireMFA(m.catalogRead)
	cfg.Roles = m.Roles
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
	group, _ := h.newOrg(owner)
	for _, a := range []iam.Actor{iam.UserActor(owner.id), iam.SystemActor()} {
		_, _, err := h.auth.MintAPIKey(ctx, a, group, iam.NewAPIKey{Name: "ci", Role: orgPersona.OwnerRole()})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, a.String())
	}
	keys, err := h.auth.APIKeys(ctx, group, iam.PageRequest{})
	require.NoError(t, err)
	require.Empty(t, keys.Items)
}

// registerApp registers a group application as registrar and gives it role.
func (h *host) registerApp(group iam.GroupRef, registrar account, slug, role string) iam.RemoteApplication {
	h.t.Helper()
	actor := iam.UserActor(registrar.id)
	app, err := h.upsertGroupApp(actor, group, slug, "https://"+slug+".security.test", publicKeyPEM(h.t), true)
	require.NoError(h.t, err)
	require.NoError(h.t, opErr(h.auth.AssignGroupRoles(h.t.Context(), actor, group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, roleIn(h.t, h.auth, group, role))))
	return app
}

// upsertGroupApp registers or updates a static-key application in group.
func (h *host) upsertGroupApp(actor iam.Actor, group iam.GroupRef, slug, iss, keyPEM string, enabled bool) (iam.RemoteApplication, error) {
	return h.auth.UpsertRemoteApplication(h.t.Context(), actor, group, iam.RemoteApplication{
		Slug: slug, Issuer: iss, PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: keyPEM}}, Enabled: enabled,
	})
}

// requireRefused: the actor lacks the authority (a capability or coverage).
func requireRefused(t *testing.T, err error) {
	t.Helper()
	require.True(t, errors.Is(err, iam.ErrInsufficientAuthority) || errors.Is(err, iam.ErrRoleAssignmentEscalation), "want an authority refusal, got %v", err)
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
// it retires and logs. No stored state keeps AuthKit from starting.
func TestSecurityCredentialSweepNeverBlocksBoot(t *testing.T) {
	ctx := context.Background()
	t.Run("RequireMFA added to a permission an application owner holds", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2aowner")
		group, _ := h.newOrg(owner)
		app := h.registerApp(group, owner, "p2a-app", "owner")
		cfg := h.cfg.engine
		m := newSecurityModel()
		m.org.RequireMFA(m.catalogRead)
		cfg.Roles = m.Roles
		h.reboot(cfg)
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)), "the application kept an owner role that needs MFA")
		require.Equal(t, orgPersona.OwnerRole(), h.roleOf(group, iam.UserSubject(owner.id)))
	})
	t.Run("2FA turned on with an application holding root owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withApps), withEngine(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
		s := newSigner(t, "p2b-kid")
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
			Slug: "p2b-app", Issuer: "https://p2b-app.security.test", PublicKeys: staticKeys(t, s), Enabled: true,
		})
		require.NoError(t, err)
		grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "owner")
		cfg := h.cfg.engine
		cfg.TwoFactor.Mode = iam.TwoFactorOptional
		h.reboot(cfg)
		require.Empty(t, h.roleOf(iam.RootGroup(), iam.RemoteApplicationSubject(app.ID)))
	})
	t.Run("a pre-0008 group registration as its group's only owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2cowner")
		group, _ := h.newOrg(owner)
		app := h.registerApp(group, owner, "p2c-app", "owner")
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
		}))
		// An account whose address nobody proved founds a group and makes its
		// own application an owner, then proves the address.
		name := unique("p2dfounder")
		email := name + "@security.test"
		u, err := h.auth.CreateUser(ctx, iam.NewUser{Email: email, Username: name, Password: password})
		require.NoError(t, err)
		group, err := h.createOrg(ctx, account{id: u.ID})
		require.NoError(t, err)
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.UserActor(u.ID), group, iam.RemoteApplication{
			Slug: "p2d-app", Issuer: "https://p2d-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "p2d-kid")), Enabled: true,
		})
		require.NoError(t, err)
		require.NoError(t, opErr(h.auth.AssignGroupRoles(ctx, iam.UserActor(u.ID), group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, orgPersona.OwnerRole())))
		require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": email}, "").status, 300)
		token := h.mail.Last(t, authtest.PasswordReset, email).Token
		resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": "Founder-proves-the-address-4"}, "")
		require.Less(t, resp.status, 300, resp.String())
		var orphaned bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT registered_by IS NULL FROM profiles.remote_applications WHERE id=$1::uuid`, app.ID).Scan(&orphaned))
		require.True(t, orphaned, "control: the first proof orphans the application")

		// A catalog change at boot sweeps the whole site.
		cfg := h.cfg.engine
		m := newSecurityModel()
		m.Root.Role("auditor", m.Root.Users.Read)
		cfg.Roles = m.Roles
		h.reboot(cfg)
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
		require.Equal(t, orgPersona.OwnerRole(), h.roleOf(group, iam.UserSubject(u.ID)))
	})
	t.Run("control: a live registrar's chosen change still keeps the last owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
		owner := h.newAccount("p2eowner")
		group, base := h.newOrg(owner)
		token := h.login(owner).AccessToken
		h.registerApp(group, owner, "p2e-app", "owner")
		resp := h.do(request{method: http.MethodDelete, path: base + "/members/" + owner.id, token: token})
		require.Equal(t, http.StatusConflict, resp.status, resp.String())
		require.Equal(t, "last_owner", resp.errorCode())
	})
}
