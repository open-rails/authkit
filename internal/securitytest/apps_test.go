package securitytest

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

const partnerIssuer = "https://partner.security.test"

// withApps is withRBAC plus remote applications on root and a root role that
// manages only credentials.
func withApps(c *authkit.Config) {
	m := newSecurityModel(authkit.RemoteApplications)
	m.Root.Role("credentials-admin", m.Root.Credentials.Manage, m.Root.Credentials.Read)
	c.Roles = m.Roles
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

// appToken is a remote-application access token the application signs with
// its own key: typ remote-application-access+jwt and no subject.
func appToken(t *testing.T, s *jwtkit.RSASigner, iss string) string {
	t.Helper()
	now := time.Now()
	token, err := jwtkit.SignWithType(context.Background(), s, jwt.MapClaims{"iss": iss, "aud": []string{audience}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}, jwtkit.RemoteApplicationAccessTokenType, true)
	require.NoError(t, err)
	return token
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
	grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "credentials-admin")
	verifies := func(token string) bool {
		_, err := h.auth.Verifier().Verify(ctx, token)
		return err == nil
	}
	require.True(t, verifies(appToken(t, partner, partnerIssuer)), "control: the partner authenticates")

	staff := h.newAccount("credstaff")
	h.grant(iam.RootGroup(), staff, "credentials-admin")
	attacker := newSigner(t, "partner-kid")
	_, err = h.auth.UpsertRemoteApplication(ctx, iam.UserActor(staff.id), iam.RootGroup(), iam.RemoteApplication{Slug: "partner", Issuer: partnerIssuer, PublicKeys: staticKeys(t, attacker), Enabled: true})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	require.ErrorIs(t, h.auth.DeleteRemoteApplication(ctx, iam.UserActor(staff.id), iam.RootGroup(), "partner"), iam.ErrInsufficientAuthority)

	stored, err := h.auth.RemoteApplication(ctx, partnerIssuer)
	require.NoError(t, err)
	require.Equal(t, staticKeys(t, partner), stored.PublicKeys)
	require.Equal(t, iam.ApplicationTrustRootManual, stored.TrustRoot)
	require.False(t, verifies(appToken(t, attacker, partnerIssuer)), "a token signed with the refused key")
	require.True(t, verifies(appToken(t, partner, partnerIssuer)))

	t.Run("a role held in another group needs coverage there", func(t *testing.T) {
		owner, manager := h.newAccount("appowner"), h.newAccount("appmanager")
		group, _ := h.newOrg(owner)
		h.grant(group, manager, "manager")
		register := func() error {
			_, err := h.upsertGroupApp(iam.UserActor(manager.id), group, "rekey-app", "https://rekey-app.security.test", publicKeyPEM(t), true)
			return err
		}
		require.NoError(t, register())
		groupApp, err := h.auth.RemoteApplication(ctx, "https://rekey-app.security.test")
		require.NoError(t, err)
		// Assignment APIs refuse a root role for an org-controlled application;
		// a row surviving from before that rule must still bind a re-key.
		_, err = h.pool.Exec(ctx, `INSERT INTO profiles.group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'credentials-admin')`, h.rootGroupID(), groupApp.ID)
		require.NoError(t, err)
		requireRefused(t, register())
		requireRefused(t, h.auth.DeleteRemoteApplication(ctx, iam.UserActor(manager.id), group, "rekey-app"))
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles WHERE remote_application_id=$1::uuid AND permission_group_id=$2::uuid`, groupApp.ID, h.rootGroupID())
		require.NoError(t, err)
		require.NoError(t, register(), "control: without the root role the manager covers it")
	})
}

// TestSecurityGroupApplicationTrustRoot (L1): a group registration is rooted
// in its group (trust root user); only the system registers an application
// its group cannot change (manual).
func TestSecurityGroupApplicationTrustRoot(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("trustowner")
	group, _ := h.newOrg(owner)
	actor := iam.UserActor(owner.id)
	const iss = "https://trust-app.security.test"
	app, err := h.upsertGroupApp(actor, group, "trust-app", iss, publicKeyPEM(t), true)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootUser, app.TrustRoot)

	app.TrustRoot = iam.ApplicationTrustRootManual
	app, err = h.auth.UpsertRemoteApplication(ctx, actor, group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootUser, app.TrustRoot, "a group actor cannot hand the application to the system")

	app.TrustRoot = iam.ApplicationTrustRootManual
	app, err = h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootManual, app.TrustRoot)
	_, err = h.upsertGroupApp(actor, group, "trust-app", iss, publicKeyPEM(t), true)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "the system's application no longer changes through its group")
	require.ErrorIs(t, h.auth.DeleteRemoteApplication(ctx, actor, group, "trust-app"), iam.ErrInsufficientAuthority)
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
	register := func(registrar account) registered {
		t.Helper()
		r := registered{registrar: registrar, slug: unique("regapp")}
		r.signer = newSigner(t, r.slug)
		actor := iam.UserActor(registrar.id)
		var err error
		r.app, err = h.auth.UpsertRemoteApplication(ctx, actor, group, iam.RemoteApplication{
			Slug: r.slug, Issuer: "https://" + r.slug + ".security.test", PublicKeys: staticKeys(t, r.signer), Enabled: true,
		})
		require.NoError(t, err)
		require.NoError(t, opErr(h.auth.AssignGroupRoles(ctx, actor, group, []iam.Subject{iam.RemoteApplicationSubject(r.app.ID)}, h.role(orgPersona, "member"))))
		return r
	}
	manager := func(prefix string) account {
		m := h.newAccount(prefix)
		h.grant(group, m, "manager")
		return m
	}
	removedManager, bannedManager, bystander := manager("regremoved"), manager("regbanned"), manager("regbystander")
	removedApp, bannedApp := register(removedManager), register(bannedManager)
	ownerApp := register(owner)

	gate := h.auth.RequirePermissionOn(group, ident.Perm("org:catalog:read"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
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
		_, err := h.upsertGroupApp(iam.APIKeyActor(key.ID), group, unique("keyapp"), "https://"+unique("keyapp")+".security.test", publicKeyPEM(t), true)
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})
	t.Run("an application never outranks its registrar", func(t *testing.T) {
		requireRefused(t, opErr(h.auth.AssignGroupRoles(ctx, iam.UserActor(owner.id), group, []iam.Subject{iam.RemoteApplicationSubject(removedApp.app.ID)}, orgPersona.OwnerRole())))
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
// through an opaque cursor.
func TestSecurityRemoteApplicationPaging(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("pageowner")
	group, _ := h.newOrg(owner)
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

// TestSecurityRemovedRoutesAreGone: v1 serves no signed-document,
// application self-registration, remote-application or custom-role route, even
// with every capability on. The catalog lists none, and a signed-in owner gets
// 404 (405 where the path serves another method). The Go operations on
// applications remain.
func TestSecurityRemovedRoutesAreGone(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withApps))
	ctx := context.Background()
	owner := h.newAccount("cutowner")
	group, base := h.newOrg(owner)
	token := h.login(owner).AccessToken
	app := h.registerApp(group, owner, "cut-app", "member")

	for _, pattern := range h.auth.Patterns() {
		for _, gone := range []string{"/.well-known/authkit/", "/applications/", "/remote-applications"} {
			require.NotContains(t, pattern, gone)
		}
	}
	require.NotContains(t, h.auth.Patterns(), "POST "+apiPrefix+"/groups/{group_id}/roles")
	require.Contains(t, h.auth.Patterns(), "GET "+apiPrefix+"/groups/{group_id}/roles", "control: the role list stays")

	for _, tc := range []struct {
		req    request
		status int
	}{
		{request{method: http.MethodGet, path: "//.well-known/authkit/documents/sha256:" + strings.Repeat("0", 64), token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/applications/register", body: map[string]string{"domain": "cut.security.test"}}, http.StatusNotFound},
		{request{method: http.MethodGet, path: base + "/remote-applications", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/remote-applications", token: token,
			body: map[string]any{"slug": "cut-new", "issuer": "https://cut-new.security.test", "public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(t)}}}}, http.StatusNotFound},
		{request{method: http.MethodDelete, path: base + "/remote-applications/cut-app", token: token}, http.StatusNotFound},
		{request{method: http.MethodPut, path: base + "/remote-applications/cut-app/roles/owner", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/roles", token: token,
			body: map[string]any{"role": "curator", "permissions": []string{"org:catalog:read"}}}, http.StatusMethodNotAllowed},
		{request{method: http.MethodDelete, path: base + "/roles/member", token: token}, http.StatusNotFound},
	} {
		resp := h.do(tc.req)
		require.Equal(t, tc.status, resp.status, "%s %s: %s", tc.req.method, tc.req.path, resp)
	}

	stored, err := h.auth.RemoteApplication(ctx, app.Issuer)
	require.NoError(t, err)
	require.True(t, stored.Enabled, "the application is untouched")
	require.Equal(t, h.role(orgPersona, "member"), h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
	_, err = h.auth.RemoteApplication(ctx, "https://cut-new.security.test")
	require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound)
	require.Equal(t, http.StatusOK, h.get(base+"/roles", token).status, "control: the role list stays")
}
