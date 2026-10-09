package securitytest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
	hauth "github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// TestSecurityDeadCreatorCredentials (H1): banning or deleting an account ends
// its API keys on the host's own routes and its invite links at once; the
// credentials never outlive the account that issued them.
func TestSecurityDeadCreatorCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(func(c *authkit.Config) {
		c.Roles.Root.Role("staff", c.Roles.Root.Users.All(), orgPersona.OwnerGrant())
	}))
	staff, founder := h.newAccount("staff"), h.newAccount("founder")
	h.grant(iam.RootGroup(), staff, "staff")
	staffToken := h.login(staff).AccessToken
	group, base := h.newOrg(founder)
	gate := verify.Required(h.auth)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
			return request{method: http.MethodPut, path: "/admin/users/" + id + "/ban", body: map[string]any{"until": nil, "reason": "spam"}, token: staffToken}
		}},
		{"delete", func(id string) request {
			return request{method: http.MethodDelete, path: "/admin/users/" + id, token: staffToken}
		}},
	} {
		t.Run(end.name, func(t *testing.T) {
			creator := h.newAccount("creator")
			h.grant(group, creator, "manager")
			token := h.login(creator).AccessToken
			key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "org:member"})
			link := h.issue(base+"/invitations", token, map[string]any{"role": "org:member"})
			require.Equal(t, http.StatusNoContent, hostRoute(key.Secret), "control: the key works while its creator is live")

			resp := h.do(end.req(creator.id))
			require.Less(t, resp.status, 300, resp.String())
			require.Equal(t, http.StatusUnauthorized, hostRoute(key.Secret))
			stranger := h.newAccount("stranger")
			resp = h.post("/invitations/redeem", map[string]string{"code": link.Code}, h.login(stranger).AccessToken)
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
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	founder := h.newAccount("n4founder")
	group, base := h.newOrg(founder)
	victim := unique("newhire") + "@security.test"
	squatter := h.register(victim)
	squatterID := h.userID(victim)
	h.grant(group, account{id: squatterID}, "manager")
	link := h.issue(base+"/invitations", squatter.AccessToken, map[string]any{"role": "org:member"})
	resp := h.post(base+"/invitations", map[string]string{"email": unique("sockpuppet") + "@security.test", "role": "org:member"}, squatter.AccessToken)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	require.True(t, liveLink(t, h, group, link.ID), "control: the squatter's link is live before the proof")

	h.proveEmail(victim, "Owner-proves-the-address-1")
	require.False(t, liveLink(t, h, group, link.ID), "the squatter's link survived the owner's proof")
	var live int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.account_registration_invites WHERE invited_by=$1::uuid AND revoked_at IS NULL`, squatterID).Scan(&live))
	require.Zero(t, live, "the squatter's account invitation survived the owner's proof")
	sockpuppet := h.newAccount("sockpuppet")
	resp = h.post("/invitations/redeem", map[string]string{"code": link.Code}, h.login(sockpuppet).AccessToken)
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
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("n8owner")
	group, base := h.newOrg(owner)
	token := h.login(owner).AccessToken
	key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "org:member"})
	s := newSigner(t, "n8-app")
	const appIssuer = "https://n8-app.security.test"
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.UserIdentity(owner.id), group, iam.RemoteApplication{
		Issuer: appIssuer, PublicKeys: staticKeys(t, s), Enabled: true,
	})
	require.NoError(t, err)
	require.NoError(t, setRole(h.auth, ctx, iam.UserIdentity(owner.id), group, iam.RemoteApplicationSubject(app.ID), roleIn(t, h.auth, group, "member")))
	hostRoute := func(auth *authkit.Client, bearer string) int {
		gate := verify.RequirePermissionOn(auth, group, ident.Perm("org:catalog:read"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		r := httptest.NewRequest(http.MethodGet, "https://host.security.test/catalog", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusNoContent, hostRoute(h.auth, key.Secret), "control: the key works")
	require.Equal(t, http.StatusNoContent, hostRoute(h.auth, appToken(t, s, appIssuer)), "control: the application works")

	// The host redeploys with org:catalog:read needing MFA.
	m := newSecurityModel()
	m.org.RequireMFA(m.catalogRead)
	rebooted := authtest.Replica(t, h.auth, authtest.WithConfig(func(c *authkit.Config) { c.Roles = m.Roles }))

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
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles))
	ctx := context.Background()
	owner := h.newAccount("nokeysowner")
	group, _ := h.newOrg(owner)
	for _, a := range []hauth.Identity{iam.UserIdentity(owner.id), iam.SystemIdentity()} {
		_, _, err := createKey(h.auth, ctx, a, group, iam.NewAPIKey{Name: "ci", Role: orgPersona.OwnerRole()})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "%+v", a)
	}
	keys, err := h.auth.ListAPIKeys(ctx, group, iam.PageRequest{})
	require.NoError(t, err)
	require.Empty(t, keys.Items)
}

// registerApp registers a group application as registrar and gives it role.
func (h *host) registerApp(group iam.GroupRef, registrar account, slug, role string) iam.RemoteApplication {
	h.t.Helper()
	who := iam.UserIdentity(registrar.id)
	app, err := h.upsertGroupApp(who, group, "https://"+slug+".security.test", publicKeyPEM(h.t), true)
	require.NoError(h.t, err)
	require.NoError(h.t, setRole(h.auth, h.t.Context(), who, group, iam.RemoteApplicationSubject(app.ID), roleIn(h.t, h.auth, group, role)))
	return app
}

// upsertGroupApp registers or updates a static-key application in group.
func (h *host) upsertGroupApp(who hauth.Identity, group iam.GroupRef, iss, keyPEM string, enabled bool) (iam.RemoteApplication, error) {
	return h.auth.UpsertRemoteApplication(h.t.Context(), who, group, iam.RemoteApplication{
		Issuer: iss, PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: keyPEM}}, Enabled: enabled,
	})
}

// requireRefused: the identity lacks the authority (a capability or coverage).
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

// TestSecurityCredentialSweepNeverBlocksBoot (P2): an application owner role
// that already confers nothing (it needs MFA, or its registrar is gone) is
// retired without the last-owner refusal, and the boot sweep never refuses:
// it retires and logs. No stored state keeps AuthKit from starting.
func TestSecurityCredentialSweepNeverBlocksBoot(t *testing.T) {
	ctx := context.Background()
	t.Run("RequireMFA added to a permission an application owner holds", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
		owner := h.newAccount("p2aowner")
		group, _ := h.newOrg(owner)
		app := h.registerApp(group, owner, "p2a-app", "owner")
		m := newSecurityModel()
		m.org.RequireMFA(m.catalogRead)
		h.replica(authtest.WithConfig(func(c *authkit.Config) { c.Roles = m.Roles }))
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)), "the application kept an owner role that needs MFA")
		require.Equal(t, orgPersona.OwnerRole(), h.roleOf(group, iam.UserSubject(owner.id)))
	})
	t.Run("2FA turned on with an application holding root owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withApps), authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
		s := newSigner(t, "p2b-kid")
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{
			Issuer: "https://p2b-app.security.test", PublicKeys: staticKeys(t, s), Enabled: true,
		})
		require.NoError(t, err)
		grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "owner")
		h.replica(authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorOptional }))
		require.Empty(t, h.roleOf(iam.RootGroup(), iam.RemoteApplicationSubject(app.ID)))
	})
	t.Run("a pre-0008 group registration as its group's only owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
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
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.role_catalogs`)
		require.NoError(t, err)
		h.replica()
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
	})
	t.Run("Required 2FA: an application orphaned by its registrar's first proof", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(func(c *authkit.Config) {
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
		app, err := h.auth.UpsertRemoteApplication(ctx, iam.UserIdentity(u.ID), group, iam.RemoteApplication{
			Issuer: "https://p2d-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "p2d-kid")), Enabled: true,
		})
		require.NoError(t, err)
		require.NoError(t, setRole(h.auth, ctx, iam.UserIdentity(u.ID), group, iam.RemoteApplicationSubject(app.ID), orgPersona.OwnerRole()))
		require.Less(t, h.post("/password/reset/request", map[string]string{"identifier": email}, "").status, 300)
		token := h.mail.Last(t, iam.MessagePasswordReset, email).Token
		resp := h.post("/password/reset/confirm", map[string]string{"token": token, "new_password": "Founder-proves-the-address-4"}, "")
		require.Less(t, resp.status, 300, resp.String())
		var orphaned bool
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT registered_by IS NULL FROM profiles.remote_applications WHERE id=$1::uuid`, app.ID).Scan(&orphaned))
		require.True(t, orphaned, "control: the first proof orphans the application")

		// A catalog change at boot sweeps the whole site.
		m := newSecurityModel()
		m.Root.Role("auditor", m.Root.Users.Read)
		h.replica(authtest.WithConfig(func(c *authkit.Config) { c.Roles = m.Roles }))
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
		require.Equal(t, orgPersona.OwnerRole(), h.roleOf(group, iam.UserSubject(u.ID)))
	})
	t.Run("control: a live registrar's chosen change still keeps the last owner", func(t *testing.T) {
		h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
		owner := h.newAccount("p2eowner")
		group, base := h.newOrg(owner)
		token := h.login(owner).AccessToken
		h.registerApp(group, owner, "p2e-app", "owner")
		resp := h.do(request{method: http.MethodDelete, path: base + "/members/users/" + owner.id, token: token})
		require.Equal(t, http.StatusConflict, resp.status, resp.String())
		require.Equal(t, "last_owner", resp.errorCode())
	})
}

// TestSecurityPerAppRoleCatalogs: apps on one account store share membership
// but each declares its own role catalog, and judges only the credentials
// issued through it. Neither app's boot sweeps the other's credentials, and a
// demotion made through one app retires what the demoted user issued through
// the other, by that app's own sweep under its own catalog.
func TestSecurityPerAppRoleCatalogs(t *testing.T) {
	const peerIssuer = "https://peer-app.security.test"
	ctx := context.Background()
	// The same role names in both apps: the issuing role manages members and
	// credentials, the other only reads.
	catalog := func(issuing string) *authkit.Roles {
		r := authkit.NewRoles()
		org := r.Persona("org", authkit.RemoteApplications, authkit.APIKeys)
		member := org.Role("member", org.Permission("catalog", "read"))
		for _, name := range []string{"manager", "curator"} {
			if name == issuing {
				org.Role(name, member, org.Members.Manage, org.Members.Read, org.Credentials.All())
			} else {
				org.Role(name, member)
			}
		}
		return r
	}
	a := newHost(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = catalog("manager")
		c.Token.AccountIssuers = []string{issuer, peerIssuer}
	}))
	onB := authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = peerIssuer
		c.Roles = catalog("curator")
	})
	founder, alice, bob := a.newAccount("pacfounder"), a.newAccount("pacalice"), a.newAccount("pacbob")
	group, _ := a.newOrg(founder)
	grantRole(t, a.auth, group, iam.UserSubject(alice.id), "manager")
	grantRole(t, a.auth, group, iam.UserSubject(bob.id), "curator")
	member := roleIn(t, a.auth, group, "member")
	keyA, _, err := createKey(a.auth, ctx, iam.UserIdentity(alice.id), group, iam.NewAPIKey{Name: "a", Role: member})
	require.NoError(t, err)
	created, err := a.auth.CreateInvitation(ctx, iam.UserIdentity(alice.id), group, iam.NewInvitation{Role: member})
	require.NoError(t, err)
	linkA := created.Invitation

	// B's first boot sweeps under B's catalog, where a manager issues nothing.
	b := a.replica(onB)
	require.True(t, liveKey(t, b, group, keyA.ID), "B's boot swept an A-issued key")
	require.True(t, liveLink(t, b, group, linkA.ID), "B's boot swept an A-issued link")
	require.Equal(t, "manager", b.roleOf(group, iam.UserSubject(alice.id)).Name(), "a role granted through A shows through B")
	_, _, err = createKey(b.auth, ctx, iam.UserIdentity(alice.id), group, iam.NewAPIKey{Name: "refused", Role: member})
	requireRefused(t, err)
	keyB, _, err := createKey(b.auth, ctx, iam.UserIdentity(bob.id), group, iam.NewAPIKey{Name: "b", Role: member})
	require.NoError(t, err)
	stamp := func(id string) (catalogIssuer string) {
		require.NoError(t, a.pool.QueryRow(ctx, `SELECT catalog_issuer FROM profiles.api_keys WHERE id = $1::uuid`, id).Scan(&catalogIssuer))
		return catalogIssuer
	}
	require.Equal(t, issuer, stamp(keyA.ID))
	require.Equal(t, peerIssuer, stamp(keyB.ID))

	// Both restart; A sweeps as on its first boot, under A's catalog, where a
	// curator issues nothing.
	_, err = a.pool.Exec(ctx, `DELETE FROM profiles.role_catalogs WHERE issuer = $1`, issuer)
	require.NoError(t, err)
	a, b = a.replica(), b.replica()
	require.True(t, liveKey(t, a, group, keyB.ID), "A's boot swept a B-issued key")
	require.True(t, liveKey(t, a, group, keyA.ID))
	require.True(t, liveLink(t, a, group, linkA.ID))
	var issuers, fingerprints []string
	require.NoError(t, a.pool.QueryRow(ctx, `SELECT array_agg(issuer ORDER BY issuer), array_agg(fingerprint ORDER BY issuer) FROM profiles.role_catalogs`).Scan(&issuers, &fingerprints))
	require.Equal(t, []string{issuer, peerIssuer}, issuers, "one catalog row per app")
	require.NotEqual(t, fingerprints[0], fingerprints[1])

	// A demotion through A leaves bob's B-issued key to B, whose sweep job
	// retires it once B's River runs.
	require.NoError(t, a.auth.Start(ctx))
	revokeRole(t, a.auth, group, iam.UserSubject(bob.id), "curator")
	require.True(t, liveKey(t, a, group, keyB.ID), "A swept a B-issued key")
	var pending int
	require.NoError(t, a.pool.QueryRow(ctx, `SELECT count(*) FROM public.river_job WHERE kind = 'authkit_credential_sweep' AND args->>'issuer' = $1 AND state = 'available'`, peerIssuer).Scan(&pending))
	require.Equal(t, 1, pending, "the demotion enqueued B's sweep")
	require.NoError(t, b.auth.Start(ctx))
	require.Eventually(t, func() bool {
		keys, err := b.auth.ListAPIKeys(ctx, group, iam.PageRequest{Limit: iam.MaxPageLimit})
		if err != nil {
			return false
		}
		for _, k := range keys.Items {
			if k.ID == keyB.ID {
				return k.RevokedAt != nil
			}
		}
		return false
	}, time.Minute, 50*time.Millisecond, "B kept a key its demoted creator no longer covers")
	require.True(t, liveKey(t, b, group, keyA.ID), "alice's authority is unchanged")
}

// TestSecurityAPIKeyResolvesOnlyAtItsApp (ak#417): apps sharing one store
// keep per-app role catalogs, so an API key resolves only at the app it was
// issued through. Presented at another app it is an invalid key, never its
// role name read under that app's catalog.
func TestSecurityAPIKeyResolvesOnlyAtItsApp(t *testing.T) {
	const peerIssuer = "https://peer-keys.security.test"
	ctx := context.Background()
	// The same role name reads at A and writes at B.
	catalog := func(action string) (*authkit.Roles, string) {
		r := authkit.NewRoles()
		org := r.Persona("org", authkit.APIKeys)
		perm := org.Permission("catalog", action)
		member := org.Role("member", perm)
		org.Role("manager", member, org.Credentials.All())
		return r, perm.String()
	}
	rolesA, readPerm := catalog("read")
	rolesB, writePerm := catalog("write")
	a := newHost(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rolesA
		c.Token.AccountIssuers = []string{issuer, peerIssuer}
	}))
	b := a.replica(authtest.WithConfig(func(c *authkit.Config) {
		c.Token.Issuer = peerIssuer
		c.Roles = rolesB
	}))
	founder, minter := a.newAccount("keyfounder"), a.newAccount("keyminter")
	group, _ := a.newOrg(founder)
	grantRole(t, a.auth, group, iam.UserSubject(minter.id), "manager")
	mint := func(h *host) string {
		_, secret, err := createKey(h.auth, ctx, iam.UserIdentity(minter.id), group, iam.NewAPIKey{Name: unique("key"), Role: roleIn(t, h.auth, group, "member")})
		require.NoError(t, err)
		return secret
	}
	for _, tc := range []struct {
		name           string
		issuing, other *host
		perm, foreign  string
	}{
		{"issued through B", b, a, writePerm, readPerm},
		{"issued through A", a, b, readPerm, writePerm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := mint(tc.issuing)
			_, err := tc.other.auth.ResolveAPIKey(ctx, secret)
			require.ErrorIs(t, err, iam.ErrAPIKeyInvalid, "a key resolved at an app it was not issued through")
			_, err = tc.other.auth.Verify(ctx, secret)
			require.ErrorIs(t, err, iam.ErrAPIKeyInvalid)
			cl, err := tc.issuing.auth.Verify(ctx, secret)
			require.NoError(t, err, "control: the issuing app resolves it")
			require.Contains(t, cl.Permissions, tc.perm)
			require.NotContains(t, cl.Permissions, tc.foreign)
		})
	}
}
