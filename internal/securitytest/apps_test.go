package securitytest

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

const partnerIssuer = "https://partner.security.test"

// withApps is withRBAC plus remote applications on root, a root role that
// manages only credentials, and published documents readable by the partner.
func withApps(c *authkit.Config) {
	m := newSecurityModel(authkit.RemoteApplications)
	m.Root.Role("credentials-admin", m.Root.Credentials.Manage, m.Root.Credentials.Read)
	c.Roles = m.Roles
	c.Documents = authkit.DocumentsConfig{Readers: []authkit.DocumentReader{{Issuer: partnerIssuer}}}
}

func pemOf(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newSigner(t *testing.T, kid string) *jwtkit.RSASigner {
	t.Helper()
	s, err := jwtkit.NewRSASigner(2048, kid)
	require.NoError(t, err)
	return s
}

func staticKeys(t *testing.T, s *jwtkit.RSASigner) []iam.RemoteApplicationKey {
	return []iam.RemoteApplicationKey{{KID: s.KID(), PublicKeyPEM: pemOf(t, s.PublicKey())}}
}

func appToken(t *testing.T, s *jwtkit.RSASigner, iss string) string {
	t.Helper()
	token, err := authkit.MintRemoteApplicationAccessToken(context.Background(), s, iam.RemoteApplicationAccess{Issuer: iss, Audiences: []string{audience}, TTL: time.Minute})
	require.NoError(t, err)
	return token.Value
}

func (h *host) rootGroupID() string {
	h.t.Helper()
	g, err := h.auth.Group(context.Background(), iam.RootGroup())
	require.NoError(h.t, err)
	return g.ID
}

// TestSecuritySystemApplicationRekey (M4): an application's keys are its
// identity and authority. A credentials manager never re-keys or deletes an
// application the system registered, and never re-keys one holding a role
// they do not cover in any group.
func TestSecuritySystemApplicationRekey(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withApps))
	ctx := context.Background()
	partner := newSigner(t, "partner-kid")
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
		Slug: "partner", Issuer: partnerIssuer, PublicKeys: staticKeys(t, partner), Enabled: true,
	})
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootManual, app.TrustRoot)
	require.Equal(t, iam.ApplicationTierApproved, app.Tier)
	doc, err := h.auth.PublishDocument(ctx, documents.Publication{Type: "example.catalog/v1", Payload: json.RawMessage(`{"catalog":true}`), Audiences: []string{"partner"}})
	require.NoError(t, err)
	readDocument := func(token string) int {
		return h.do(request{method: http.MethodGet, path: "/" + documents.PublicationPathPrefix + doc.Digest, token: token}).status
	}
	require.Equal(t, http.StatusOK, readDocument(appToken(t, partner, partnerIssuer)), "control: the partner reads its document")

	staff := h.newAccount("credstaff")
	h.grant(iam.RootGroup(), staff, "credentials-admin")
	staffToken := h.login(staff).AccessToken
	attacker := newSigner(t, "partner-kid")
	resp := h.post("/groups/"+h.rootGroupID()+"/remote-applications", map[string]any{"slug": "partner", "issuer": partnerIssuer,
		"public_keys": []map[string]string{{"kid": "partner-kid", "public_key_pem": pemOf(t, attacker.PublicKey())}}}, staffToken)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	_, err = h.auth.UpsertRemoteApplication(ctx, iam.UserActor(staff.id), iam.RootGroup(), iam.RemoteApplication{Slug: "partner", Issuer: partnerIssuer, PublicKeys: staticKeys(t, attacker), Enabled: true})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	resp = h.do(request{method: http.MethodDelete, path: "/groups/" + h.rootGroupID() + "/remote-applications/partner", token: staffToken})
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())

	stored, err := h.auth.RemoteApplication(ctx, partnerIssuer)
	require.NoError(t, err)
	require.Equal(t, staticKeys(t, partner), stored.PublicKeys)
	require.Equal(t, iam.ApplicationTierApproved, stored.Tier)
	require.Equal(t, iam.ApplicationTrustRootManual, stored.TrustRoot)
	require.Equal(t, http.StatusUnauthorized, readDocument(appToken(t, attacker, partnerIssuer)), "a token signed with the refused key")
	require.Equal(t, http.StatusOK, readDocument(appToken(t, partner, partnerIssuer)))

	t.Run("a role held in another group needs coverage there", func(t *testing.T) {
		owner, manager := h.newAccount("appowner"), h.newAccount("appmanager")
		group, base := h.newOrg(owner)
		h.grant(group, manager, "manager")
		managerToken := h.login(manager).AccessToken
		register := func() response {
			return h.post(base+"/remote-applications", map[string]any{"slug": "rekey-app", "issuer": "https://rekey-app.security.test",
				"public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(t)}}}, managerToken)
		}
		require.Equal(t, http.StatusCreated, register().status)
		groupApp, err := h.auth.RemoteApplication(ctx, "https://rekey-app.security.test")
		require.NoError(t, err)
		// Assignment APIs refuse a root role for an org-controlled application;
		// a row surviving from before that rule must still bind a re-key.
		_, err = h.pool.Exec(ctx, `INSERT INTO profiles.group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'credentials-admin')`, h.rootGroupID(), groupApp.ID)
		require.NoError(t, err)
		resp := register()
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		resp = h.do(request{method: http.MethodDelete, path: base + "/remote-applications/rekey-app", token: managerToken})
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles WHERE remote_application_id=$1::uuid AND permission_group_id=$2::uuid`, groupApp.ID, h.rootGroupID())
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, register().status, "control: without the root role the manager covers it")
	})
}

// TestSecurityGroupApplicationTier (L1): approval is the system's act. A
// group registration starts at tier registered, and a group re-key of an
// approved application drops it back.
func TestSecurityGroupApplicationTier(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("tierowner")
	group, base := h.newOrg(owner)
	token := h.login(owner).AccessToken
	key := publicKeyPEM(t)
	register := func(key string, extra map[string]any) response {
		body := map[string]any{"slug": "tier-app", "issuer": "https://tier-app.security.test", "public_keys": []map[string]string{{"public_key_pem": key}}}
		for k, v := range extra {
			body[k] = v
		}
		return h.post(base+"/remote-applications", body, token)
	}
	resp := register(key, nil)
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	var out struct {
		Tier      string `json:"tier"`
		TrustRoot string `json:"trust_root"`
	}
	resp.json(t, &out)
	require.Equal(t, string(iam.ApplicationTierRegistered), out.Tier)
	require.Equal(t, string(iam.ApplicationTrustRootUser), out.TrustRoot)

	app, err := h.auth.RemoteApplication(ctx, "https://tier-app.security.test")
	require.NoError(t, err)
	app.Tier = iam.ApplicationTierApproved
	app, err = h.auth.UpsertRemoteApplication(ctx, iam.UserActor(owner.id), group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTierRegistered, app.Tier, "a group actor cannot approve")

	app.Tier = iam.ApplicationTierApproved
	app, err = h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTierApproved, app.Tier)
	resp = register(key, map[string]any{"enabled": false})
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	resp.json(t, &out)
	require.Equal(t, string(iam.ApplicationTierApproved), out.Tier, "an update keeping the keys keeps the approval")
	resp = register(publicKeyPEM(t), nil)
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	resp.json(t, &out)
	require.Equal(t, string(iam.ApplicationTierRegistered), out.Tier, "a re-key needs a new approval")
}

// TestSecurityApplicationMFARoles (L2): an application cannot enroll a second
// factor, so it never holds an MFA-required role and never stands in for the
// MFA owner of a group whose owners need one.
func TestSecurityApplicationMFARoles(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withApps))
	ctx := context.Background()
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
		Slug: "root-app", Issuer: "https://root-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "root-app")), Enabled: true,
	})
	require.NoError(t, err)
	res, err := h.auth.AssignGroupRoles(ctx, iam.SystemActor(), iam.RootGroup(), []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, iam.RootPersona.OwnerRole())
	require.NoError(t, err)
	require.ErrorIs(t, res[0].Err, iam.ErrRoleNotAssignable)
	grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "credentials-admin")

	owner := h.newAccount("mfaowner")
	h.enrollEmail2FA(owner)
	grantRole(t, h.auth, iam.RootGroup(), iam.UserSubject(owner.id), "owner")
	// An owner row for the application from before this rule.
	_, err = h.pool.Exec(ctx, `UPDATE profiles.group_remote_application_roles SET role='owner' WHERE remote_application_id=$1::uuid`, app.ID)
	require.NoError(t, err)
	res, err = h.auth.UnassignGroupRoles(ctx, iam.SystemActor(), iam.RootGroup(), []iam.Subject{iam.UserSubject(owner.id)}, iam.RootPersona.OwnerRole())
	require.NoError(t, err)
	require.ErrorIs(t, res[0].Err, iam.ErrLastOwner, "the application counted as the MFA owner")
	roles, err := h.auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(owner.id)})
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona.OwnerRole(), roles[iam.UserSubject(owner.id)])
	// Whatever path left the row, the role confers nothing on the application.
	authority, err := h.auth.RemoteApplicationAuthority(ctx, app.ID)
	require.NoError(t, err)
	require.Empty(t, authority.Permissions)
	can, err := h.auth.Can(ctx, iam.RemoteApplicationActor(app.ID), iam.RootGroup(), iam.PermRootUsersRead)
	require.NoError(t, err)
	require.False(t, can)

	t.Run("bootstrap hands an application no MFA-required root role", func(t *testing.T) {
		enabled := true
		_, err := h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{{
			Slug: "boot-app", Issuer: "https://boot-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "boot-app")), Enabled: &enabled, RootRole: iam.RootPersona.OwnerRole(),
		}}}, iam.BootstrapOptions{})
		require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
		_, err = h.auth.RemoteApplication(ctx, "https://boot-app.security.test")
		require.Error(t, err, "the refused manifest left its application behind")
	})
}

// TestSecurityApplicationRegistrar (N3): a group-registered application is a
// credential of the user who supplied its keys. A machine actor cannot
// register one, it holds only roles its registrar could issue, and its roles
// end when the registrar is removed from the group or banned.
func TestSecurityApplicationRegistrar(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("regowner")
	group, base := h.newOrg(owner)
	ownerToken := h.login(owner).AccessToken
	type registered struct {
		registrar account
		slug      string
		signer    *jwtkit.RSASigner
		app       iam.RemoteApplication
	}
	// register has registrar (a manager, or the owner) register an application
	// holding member. Every application is registered before the first token
	// is verified: the verifier refreshes its application set on a timer.
	register := func(registrar account, token string) registered {
		t.Helper()
		r := registered{registrar: registrar, slug: unique("regapp")}
		r.signer = newSigner(t, r.slug)
		resp := h.post(base+"/remote-applications", map[string]any{"slug": r.slug, "issuer": "https://" + r.slug + ".security.test",
			"public_keys": []map[string]string{{"kid": r.signer.KID(), "public_key_pem": pemOf(t, r.signer.PublicKey())}}}, token)
		require.Equal(t, http.StatusCreated, resp.status, resp.String())
		var err error
		r.app, err = h.auth.RemoteApplication(ctx, "https://"+r.slug+".security.test")
		require.NoError(t, err)
		resp = h.do(request{method: http.MethodPut, path: base + "/remote-applications/" + r.slug + "/roles/member", token: token})
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		return r
	}
	manager := func(prefix string) (account, string) {
		m := h.newAccount(prefix)
		h.grant(group, m, "manager")
		return m, h.login(m).AccessToken
	}
	removedManager, removedToken := manager("regremoved")
	bannedManager, bannedToken := manager("regbanned")
	bystander, _ := manager("regbystander")
	removedApp, bannedApp := register(removedManager, removedToken), register(bannedManager, bannedToken)
	ownerApp := register(owner, ownerToken)

	gate := h.auth.RequirePermission(group, ident.Perm("org:catalog:read"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	hostRoute := func(r registered) int {
		req := httptest.NewRequest(http.MethodGet, "https://host.security.test/catalog", nil)
		req.Header.Set("Authorization", "Bearer "+appToken(t, r.signer, r.app.Issuer))
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, req)
		return w.Code
	}
	for _, r := range []registered{removedApp, bannedApp, ownerApp} {
		require.Equal(t, http.StatusNoContent, hostRoute(r), "control: an application works while its registrar does")
	}

	t.Run("an API key registers no application", func(t *testing.T) {
		key := h.issue(base+"/api-keys", ownerToken, map[string]any{"name": "ci", "role": "manager"})
		resp := h.post(base+"/remote-applications", map[string]any{"slug": unique("keyapp"), "issuer": "https://" + unique("keyapp") + ".security.test",
			"public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(t)}}}, key.Secret)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	})
	t.Run("an application never outranks its registrar", func(t *testing.T) {
		resp := h.do(request{method: http.MethodPut, path: base + "/remote-applications/" + removedApp.slug + "/roles/owner", token: ownerToken})
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.RemoteApplicationSubject(removedApp.app.ID)})
		require.NoError(t, err)
		require.Equal(t, h.role(orgPersona, "member"), roles[iam.RemoteApplicationSubject(removedApp.app.ID)])
	})
	for _, tc := range []struct {
		name string
		app  registered
		end  func(a account)
	}{
		{"the registrar is removed from the group", removedApp, func(a account) {
			resp := h.do(request{method: http.MethodDelete, path: base + "/members/" + a.id, token: ownerToken})
			require.Less(t, resp.status, 300, resp.String())
		}},
		{"the registrar is banned", bannedApp, func(a account) {
			require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), a.id, iam.Ban{Reason: "abuse"}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.end(tc.app.registrar)
			roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.RemoteApplicationSubject(tc.app.app.ID)})
			require.NoError(t, err)
			require.Empty(t, roles, "the application kept its role past its registrar's authority")
			require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, hostRoute(tc.app))
		})
	}
	t.Run("control: another registrar's application survives a manager's removal", func(t *testing.T) {
		resp := h.do(request{method: http.MethodDelete, path: base + "/members/" + bystander.id, token: ownerToken})
		require.Less(t, resp.status, 300, resp.String())
		require.Equal(t, http.StatusNoContent, hostRoute(ownerApp))
	})
}

// TestSecurityDelegatedPrincipalManagementPlane (L3): with overlapping
// audiences a delegated token verifies at AuthKit itself, but it is a snapshot
// of its user's authority: AuthKit's own routes refuse it, and host gates
// re-check it against the user's live, ban-aware authority.
func TestSecurityDelegatedPrincipalManagementPlane(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		c.Delegated = authkit.DelegatedConfig{Audiences: []string{audience}}
	}), func(c *hostConfig) {
		c.deps.DelegatedAuthorization = func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{Permissions: []string{iam.PermRootUsersRead.String()}}, nil
		}
	})
	ctx := context.Background()
	admin := h.newAccount("delegadmin")
	h.grant(iam.RootGroup(), admin, "admin")
	require.Equal(t, http.StatusOK, h.get("/admin/users", h.login(admin).AccessToken).status, "control: the user reads the directory")
	token, err := h.auth.MintDelegatedAccessToken(ctx, iam.UserActor(admin.id), iam.DelegatedAccess{Audiences: []string{audience}, Permissions: []string{iam.PermRootUsersRead.String()}})
	require.NoError(t, err)
	cl, err := h.auth.Verifier().Verify(ctx, token.Value)
	require.NoError(t, err, "overlapping audiences: the delegated token verifies here")
	perm := iam.Perm(iam.PermRootUsersRead)
	allowed, err := verify.Allow(ctx, h.auth, cl, perm, iam.RootGroup())
	require.NoError(t, err)
	require.True(t, allowed)

	resp := h.get("/admin/users", token.Value)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	resp = h.get("/admin/users/"+admin.id, token.Value)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())

	_, err = h.pool.Exec(ctx, `UPDATE profiles.users SET banned_at=now(), ban_reason='test' WHERE id=$1::uuid`, admin.id)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, h.get("/admin/users", token.Value).status)
	allowed, err = verify.Allow(ctx, h.auth, cl, perm, iam.RootGroup())
	require.NoError(t, err)
	require.False(t, allowed, "a banned user's delegated token kept its authority")
}

// TestSecurityDelegatedMintAuthority: the grant check runs on the Go path too.
// A user mints only for itself and only AuthKit authority it holds live;
// machine actors never mint; the system is trusted.
func TestSecurityDelegatedMintAuthority(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	moderator, other := h.newAccount("mintmod"), h.newAccount("mintother")
	h.grant(iam.RootGroup(), moderator, "moderator")
	mint := func(a iam.Actor, d iam.DelegatedAccess) error {
		d.Audiences = []string{"resource.security.test"}
		_, err := h.auth.MintDelegatedAccessToken(ctx, a, d)
		return err
	}
	require.NoError(t, mint(iam.UserActor(moderator.id), iam.DelegatedAccess{Permissions: []string{iam.PermRootUsersBan.String(), "resource:read"}}))
	require.ErrorIs(t, mint(iam.UserActor(moderator.id), iam.DelegatedAccess{Permissions: []string{iam.PermRootUsersManage.String()}}), iam.ErrDelegationRefused)
	require.ErrorIs(t, mint(iam.UserActor(moderator.id), iam.DelegatedAccess{Permissions: []string{"root:*"}}), iam.ErrDelegationRefused)
	require.ErrorIs(t, mint(iam.UserActor(moderator.id), iam.DelegatedAccess{Subject: other.id}), iam.ErrInsufficientAuthority)
	for _, a := range []iam.Actor{{}, iam.APIKeyActor("0190f000-0000-7000-8000-000000000001"), iam.RemoteApplicationActor("0190f000-0000-7000-8000-000000000002")} {
		require.Error(t, mint(a, iam.DelegatedAccess{Subject: moderator.id}), a.String())
	}
	require.Error(t, mint(iam.SystemActor(), iam.DelegatedAccess{}), "the system names the subject")
	require.NoError(t, mint(iam.SystemActor(), iam.DelegatedAccess{Subject: other.id, Permissions: []string{iam.PermRootUsersManage.String()}}))

	_, err := h.pool.Exec(ctx, `UPDATE profiles.users SET banned_at=now(), ban_reason='test' WHERE id=$1::uuid`, moderator.id)
	require.NoError(t, err)
	require.ErrorIs(t, mint(iam.UserActor(moderator.id), iam.DelegatedAccess{Permissions: []string{"resource:read"}}), iam.ErrInsufficientAuthority)
}

// TestSecurityIssuerSquatLastOwner (L6): an unproven issuer claim never keeps
// the issuer from the domain that proves it, even when the squatting
// application is left as the last owner of its group.
func TestSecurityIssuerSquatLastOwner(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC), withEngine(func(c *authkit.Config) {
		c.Applications = authkit.ApplicationsConfig{SelfRegistration: true, AllowPrivateNetworkJWKS: true, OrgPersona: orgPersona}
	}))
	ctx := context.Background()
	squatter := h.newAccount("lastsquatter")
	_, base := h.newOrg(squatter)
	token := h.login(squatter).AccessToken
	const victimIssuer = "https://last-owner-victim.security.test"
	resp := h.post(base+"/remote-applications", map[string]any{"slug": "squat-app", "issuer": victimIssuer,
		"public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(t)}}}, token)
	require.Equal(t, http.StatusCreated, resp.status, resp.String())
	resp = h.do(request{method: http.MethodPut, path: base + "/remote-applications/squat-app/roles/owner", token: token})
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	// The registrar cannot leave its application as the last owner (the
	// application's roles go with the registrar's), so shape that state here.
	resp = h.do(request{method: http.MethodDelete, path: base + "/members/" + squatter.id, token: token})
	require.Equal(t, http.StatusConflict, resp.status, resp.String())
	_, err := h.pool.Exec(ctx, `DELETE FROM profiles.group_user_roles WHERE user_id=$1::uuid`, squatter.id)
	require.NoError(t, err)

	doc, err := json.Marshal(iam.ApplicationDocument{Slug: unique("lastvictim"), Issuer: victimIssuer,
		PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: publicKeyPEM(t)}}})
	require.NoError(t, err)
	domain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != iam.ApplicationWellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(domain.Close)
	resp = h.post("/applications/register", map[string]string{"domain": domain.URL}, "")
	require.Equal(t, http.StatusCreated, resp.status, "the squatter kept the issuer from its domain: %s", resp)
	app, err := h.auth.RemoteApplication(ctx, victimIssuer)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootDomain, app.TrustRoot)
	require.Equal(t, iam.ApplicationTierRegistered, app.Tier)
}

// TestSecurityTokenMatrix (invariant 7): typ × subject claims × sender binding
// × issuer kind. Only the allowed shapes verify, each derives the one actor its
// shape implies (never the system), and AuthKit's management routes refuse
// every delegated principal that verifies.
func TestSecurityTokenMatrix(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	user := h.newAccount("matrixuser")
	h.grant(iam.RootGroup(), user, "admin")
	_, base := h.newOrg(user)
	managed, foreign := newSigner(t, "managed-kid"), newSigner(t, "foreign-kid")
	const managedIssuer, foreignIssuer = "https://managed.security.test", "https://foreign.security.test"
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), iam.RemoteApplication{
		Slug: "managed", Issuer: managedIssuer, PublicKeys: staticKeys(t, managed), Enabled: true,
	})
	require.NoError(t, err)
	ver := h.auth.Verifier()
	require.NoError(t, ver.AddIssuer(foreignIssuer, []string{audience}, verify.IssuerOptions{Keys: []verify.IssuerKey{{KID: foreign.KID(), PublicKeyPEM: pemOf(t, foreign.PublicKey())}}}))
	leafDER, err := base64.RawURLEncoding.DecodeString(delegateCertificate(t))
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	issuers := []struct {
		name, iss string
		signer    *jwtkit.RSASigner
	}{{"local", issuer, signer()}, {"managed", managedIssuer, managed}, {"foreign", foreignIssuer, foreign}}
	typs := []string{jwtkit.AccessTokenType, jwtkit.DelegatedAccessTokenType, jwtkit.RemoteApplicationAccessTokenType, "service+jwt", ""}
	subjects := []string{"sub", "delegated_sub", "both", "none"}
	allowed := map[[3]string]bool{
		{"local", jwtkit.AccessTokenType, "sub"}:                      true,
		{"local", jwtkit.DelegatedAccessTokenType, "delegated_sub"}:   true,
		{"managed", jwtkit.DelegatedAccessTokenType, "delegated_sub"}: true,
		{"managed", jwtkit.RemoteApplicationAccessTokenType, "none"}:  true,
		{"foreign", jwtkit.AccessTokenType, "sub"}:                    true,
		{"foreign", jwtkit.DelegatedAccessTokenType, "delegated_sub"}: true,
	}
	for _, is := range issuers {
		for _, typ := range typs {
			for _, subject := range subjects {
				for _, bound := range []bool{false, true} {
					now := time.Now()
					claims := jwt.MapClaims{"iss": is.iss, "aud": []string{audience}, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": unique("jti")}
					if subject == "sub" || subject == "both" {
						claims["sub"] = user.id
					}
					if subject == "delegated_sub" || subject == "both" {
						claims["delegated_sub"] = user.id
					}
					if is.name == "local" && typ == jwtkit.DelegatedAccessTokenType {
						claims["permissions"] = []string{iam.PermRootUsersRead.String()}
					}
					if bound {
						claims[jwtkit.ConfirmationClaim] = jwtkit.ConfirmationClaimValue(jwtkit.CertificateSHA256(leaf.Raw))
					}
					headers := map[string]any{}
					if typ != "" {
						headers["typ"] = typ
					}
					token, err := is.signer.SignWithHeaders(ctx, claims, headers)
					require.NoError(t, err)
					req := httptest.NewRequest(http.MethodGet, "https://resource.security.test/", nil)
					req.Header.Set("Authorization", "Bearer "+token)
					if bound {
						req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
					}
					name := is.name + "/" + typ + "/" + subject
					if bound {
						name += "/cnf"
					}
					cl, err := ver.VerifyRequest(req)
					want := allowed[[3]string{is.name, typ, subject}] && (!bound || typ == jwtkit.DelegatedAccessTokenType)
					if !want {
						require.Error(t, err, name)
						continue
					}
					require.NoError(t, err, name)
					actor, ok := verify.ActorFromClaims(cl)
					require.NotEqual(t, iam.ActorSystem, actor.Kind(), name)
					switch {
					case typ == jwtkit.AccessTokenType && is.name == "local":
						require.True(t, ok, name)
						require.Equal(t, iam.UserActor(user.id), actor, name)
					case typ == jwtkit.AccessTokenType:
						require.False(t, ok, "a foreign user has no AuthKit authority: %s", name)
					case typ == jwtkit.RemoteApplicationAccessTokenType:
						require.Equal(t, iam.ActorRemoteApplication, actor.Kind(), name)
						require.Equal(t, app.ID, actor.ID(), name)
					default:
						require.Equal(t, iam.ActorDelegated, actor.Kind(), name)
						grant, _ := actor.Delegation()
						require.Equal(t, is.iss, grant.Issuer, name)
						if is.name == "managed" {
							require.Equal(t, app.ID, grant.RemoteApplicationID, name)
						}
						if !bound {
							resp := h.get("/admin/users", token)
							require.Equal(t, http.StatusForbidden, resp.status, "%s: %s", name, resp)
							resp = h.get(base+"/members", token)
							require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.status, "%s: %s", name, resp)
						}
					}
				}
			}
		}
	}
	require.Equal(t, http.StatusOK, h.get("/admin/users", h.login(user).AccessToken).status, "control: the user reads the directory")
}

// TestSecurityRemoteApplicationPaging: a group's applications list in pages
// through an opaque cursor, over Go and HTTP alike.
func TestSecurityRemoteApplicationPaging(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("pageowner")
	group, base := h.newOrg(owner)
	for _, slug := range []string{"page-a", "page-b", "page-c"} {
		_, err := h.auth.UpsertRemoteApplication(ctx, iam.UserActor(owner.id), group, iam.RemoteApplication{
			Slug: slug, Issuer: "https://" + slug + ".security.test", PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: publicKeyPEM(t)}}, Enabled: true,
		})
		require.NoError(t, err)
	}
	first, err := h.auth.RemoteApplications(ctx, group, iam.PageRequest{Limit: 2})
	require.NoError(t, err)
	require.Len(t, first.Items, 2)
	require.NotEmpty(t, first.Next)
	second, err := h.auth.RemoteApplications(ctx, group, iam.PageRequest{Cursor: first.Next, Limit: 2})
	require.NoError(t, err)
	require.Len(t, second.Items, 1)
	require.Empty(t, second.Next)
	var slugs []string
	for _, a := range append(first.Items, second.Items...) {
		slugs = append(slugs, a.Slug)
	}
	require.Equal(t, []string{"page-c", "page-b", "page-a"}, slugs, "newest first, no repeats")
	_, err = h.auth.RemoteApplications(ctx, group, iam.PageRequest{Cursor: "not-a-cursor"})
	require.Error(t, err)

	token := h.login(owner).AccessToken
	resp := h.get(base+"/remote-applications?limit=2", token)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var page struct {
		Data []struct {
			Slug string `json:"slug"`
		} `json:"data"`
		NextCursor string `json:"next_cursor"`
	}
	resp.json(t, &page)
	require.Len(t, page.Data, 2)
	require.Equal(t, first.Next, page.NextCursor)
	resp = h.get(base+"/remote-applications?cursor="+page.NextCursor, token)
	require.Equal(t, http.StatusOK, resp.status, resp.String())
	var last struct {
		Data       []json.RawMessage `json:"data"`
		NextCursor string            `json:"next_cursor"`
	}
	resp.json(t, &last)
	require.Len(t, last.Data, 1)
	require.Empty(t, last.NextCursor)
	require.Equal(t, http.StatusBadRequest, h.get(base+"/remote-applications?limit=zero", token).status)
}

// TestSecurityServiceJWTPermissionsOnly: a service JWT's authority is its
// permissions claim; an OAuth scope claim grants nothing.
func TestSecurityServiceJWTPermissionsOnly(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	ctx := context.Background()
	token, minted, err := h.auth.MintServiceJWT(ctx, iam.ServiceJWT{Subject: "billing", Audiences: []string{audience}, Permissions: []string{"ledger:write"}})
	require.NoError(t, err)
	require.Equal(t, minted.ExpiresAt, token.ExpiresAt)
	cl, err := h.auth.Verifier().VerifyServiceJWT(ctx, token.Value)
	require.NoError(t, err)
	require.Equal(t, []string{"ledger:write"}, cl.Permissions)

	now := time.Now()
	scoped, err := signer().SignWithHeaders(ctx, jwt.MapClaims{
		"iss": issuer, "sub": "billing", "aud": []string{audience}, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "jti": unique("svc"), "token_use": iam.ServiceJWTTokenUse, "scope": "ledger:write",
	}, map[string]any{"typ": "service+jwt"})
	require.NoError(t, err)
	cl, err = h.auth.Verifier().VerifyServiceJWT(ctx, scoped)
	require.NoError(t, err)
	require.Empty(t, cl.Permissions, "scope became permissions")
}
