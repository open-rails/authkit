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
// minted by a user or the operator.
func TestSecurityAPIKeysNeedPersonaOptIn(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles))
	ctx := context.Background()
	owner := h.newAccount("nokeysowner")
	group, _ := h.newOrg("nokeys", owner)
	for _, a := range []iam.Actor{iam.UserActor(owner.id), iam.OperatorActor()} {
		_, _, err := h.auth.MintAPIKey(ctx, a, group, iam.NewAPIKey{Name: "ci", Role: iam.OwnerRole})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, a.String())
	}
	keys, err := h.auth.APIKeys(ctx, group, iam.PageRequest{})
	require.NoError(t, err)
	require.Empty(t, keys.Items)
}
