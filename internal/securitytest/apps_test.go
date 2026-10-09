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
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
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

func newSigner(t *testing.T, kid string) keys.Signer {
	t.Helper()
	s := testkeys.RSA(kid)
	return s
}

func staticKeys(t *testing.T, s keys.Signer) []iam.RemoteApplicationKey {
	return []iam.RemoteApplicationKey{{KID: s.KID(), PublicKeyPEM: pemOf(t, s.Public())}}
}

func (h *host) rootGroupID() string {
	h.t.Helper()
	g, err := h.auth.Group(context.Background(), iam.RootGroup())
	require.NoError(h.t, err)
	return g.ID
}

// TestSecuritySystemApplicationRekey (M4): an application's keys are its
// identity and authority to the resource servers that trust the registry. A credentials manager never re-keys or deletes an
// application the system registered, and never re-keys one holding a role
// they do not cover in any group.
func TestSecuritySystemApplicationRekey(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withApps))
	ctx := context.Background()
	partner := newSigner(t, "partner-kid")
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{
		Issuer: partnerIssuer, PublicKeys: staticKeys(t, partner), Enabled: true,
	})
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootManual, app.TrustRoot)
	grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "credentials-admin")

	staff := h.newAccount("credstaff")
	h.grant(iam.RootGroup(), staff, "credentials-admin")
	attacker := newSigner(t, "partner-kid")
	_, err = h.auth.UpsertRemoteApplication(ctx, iam.UserIdentity(staff.id), iam.RootGroup(), iam.RemoteApplication{Issuer: partnerIssuer, PublicKeys: staticKeys(t, attacker), Enabled: true})
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	require.ErrorIs(t, h.auth.DeleteRemoteApplication(ctx, iam.UserIdentity(staff.id), iam.RootGroup(), app.ID), iam.ErrInsufficientAuthority)

	stored, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer(partnerIssuer))
	require.NoError(t, err)
	require.Equal(t, staticKeys(t, partner), stored.PublicKeys)
	require.Equal(t, iam.ApplicationTrustRootManual, stored.TrustRoot)
	require.NotEqual(t, staticKeys(t, attacker), stored.PublicKeys, "the refused key is not the application's")

	t.Run("a role held in another group needs coverage there", func(t *testing.T) {
		owner, manager := h.newAccount("appowner"), h.newAccount("appmanager")
		group, _ := h.newOrg(owner)
		h.grant(group, manager, "manager")
		register := func() error {
			_, err := h.upsertGroupApp(iam.UserIdentity(manager.id), group, "https://rekey-app.security.test", publicKeyPEM(t), true)
			return err
		}
		require.NoError(t, register())
		groupApp, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://rekey-app.security.test"))
		require.NoError(t, err)
		// Assignment APIs refuse a root role for an org-controlled application;
		// a row surviving from before that rule must still bind a re-key.
		_, err = h.pool.Exec(ctx, `INSERT INTO profiles.group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'root:credentials-admin')`, h.rootGroupID(), groupApp.ID)
		require.NoError(t, err)
		requireRefused(t, register())
		requireRefused(t, h.auth.DeleteRemoteApplication(ctx, iam.UserIdentity(manager.id), group, groupApp.ID))
		_, err = h.pool.Exec(ctx, `DELETE FROM profiles.group_remote_application_roles WHERE remote_application_id=$1::uuid AND permission_group_id=$2::uuid`, groupApp.ID, h.rootGroupID())
		require.NoError(t, err)
		require.NoError(t, register(), "control: without the root role the manager covers it")
	})
}

// TestSecurityGroupApplicationTrustRoot (L1): a group registration is rooted
// in its group (trust root user); only the system registers an application
// its group cannot change (manual).
func TestSecurityGroupApplicationTrustRoot(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("trustowner")
	group, _ := h.newOrg(owner)
	who := iam.UserIdentity(owner.id)
	const iss = "https://trust-app.security.test"
	app, err := h.upsertGroupApp(who, group, iss, publicKeyPEM(t), true)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootUser, app.TrustRoot)

	app.TrustRoot = iam.ApplicationTrustRootManual
	app, err = h.auth.UpsertRemoteApplication(ctx, who, group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootUser, app.TrustRoot, "a group member cannot hand the application to the system")

	app.TrustRoot = iam.ApplicationTrustRootManual
	app, err = h.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), group, app)
	require.NoError(t, err)
	require.Equal(t, iam.ApplicationTrustRootManual, app.TrustRoot)
	_, err = h.upsertGroupApp(who, group, iss, publicKeyPEM(t), true)
	require.ErrorIs(t, err, iam.ErrInsufficientAuthority, "the system's application no longer changes through its group")
	require.ErrorIs(t, h.auth.DeleteRemoteApplication(ctx, who, group, app.ID), iam.ErrInsufficientAuthority)
}

// TestSecurityApplicationMFARoles (L2): an application cannot enroll a second
// factor, so it never holds an MFA-required role and never stands in for the
// MFA owner of a group whose owners need one.
func TestSecurityApplicationMFARoles(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withApps))
	ctx := context.Background()
	app, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{
		Issuer: "https://root-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "root-app")), Enabled: true,
	})
	require.NoError(t, err)
	require.ErrorIs(t, setRole(h.auth, ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), iam.RootPersona().OwnerRole()), iam.ErrRoleNotAssignable)
	grantRole(t, h.auth, iam.RootGroup(), iam.RemoteApplicationSubject(app.ID), "credentials-admin")

	owner := h.newAccount("mfaowner")
	h.enrollEmail2FA(owner)
	grantRole(t, h.auth, iam.RootGroup(), iam.UserSubject(owner.id), "owner")
	// An owner row for the application from before this rule.
	_, err = h.pool.Exec(ctx, `UPDATE profiles.group_remote_application_roles SET role='root:owner' WHERE remote_application_id=$1::uuid`, app.ID)
	require.NoError(t, err)
	require.ErrorIs(t, h.auth.RemoveGroupMember(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(owner.id), authkit.IfRole(iam.RootPersona().OwnerRole())), iam.ErrLastOwner, "the application counted as the MFA owner")
	roles, err := h.auth.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(owner.id)})
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona().OwnerRole(), roles[iam.UserSubject(owner.id)])
	// Whatever path left the row, the role confers nothing on the application.
	stored, err := h.auth.RemoteApplication(ctx, iam.AppByID(app.ID))
	require.NoError(t, err)
	require.Equal(t, iam.RootPersona().OwnerRole(), stored.Role)
	require.Empty(t, stored.Permissions)
	can, err := h.auth.Can(ctx, iam.ApplicationIdentity(app.ID), iam.RootGroup(), ident.RootUsersRead)
	require.NoError(t, err)
	require.False(t, can)

	t.Run("bootstrap hands an application no MFA-required root role", func(t *testing.T) {
		enabled := true
		_, err := h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{{
			Issuer: "https://boot-app.security.test", PublicKeys: staticKeys(t, newSigner(t, "boot-app")), Enabled: &enabled, RootRole: iam.RootPersona().OwnerRole(),
		}}}, iam.BootstrapOptions{})
		require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
		_, err = h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://boot-app.security.test"))
		require.Error(t, err, "the refused manifest left its application behind")
	})
}

// TestSecurityApplicationRegistrar (N3): a group-registered application is a
// credential of the user who supplied its keys. A machine identity cannot
// register one, it holds only roles its registrar could issue, and its roles
// end when the registrar is removed from the group or banned.
func TestSecurityApplicationRegistrar(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("regowner")
	group, base := h.newOrg(owner)
	ownerToken := h.login(owner).AccessToken
	type registered struct {
		registrar account
		slug      string
		signer    keys.Signer
		app       iam.RemoteApplication
	}
	// register has registrar (a manager, or the owner) register an application
	// holding member.
	register := func(registrar account) registered {
		t.Helper()
		r := registered{registrar: registrar, slug: unique("regapp")}
		r.signer = newSigner(t, r.slug)
		who := iam.UserIdentity(registrar.id)
		var err error
		r.app, err = h.auth.UpsertRemoteApplication(ctx, who, group, iam.RemoteApplication{
			Issuer: "https://" + r.slug + ".security.test", PublicKeys: staticKeys(t, r.signer), Enabled: true,
		})
		require.NoError(t, err)
		require.NoError(t, setRole(h.auth, ctx, who, group, iam.RemoteApplicationSubject(r.app.ID), h.role(orgPersona, "member")))
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

	// What the application may do, as a resource server trusting the
	// registry asks it.
	canRead := func(r registered) bool {
		ok, err := h.auth.Can(ctx, iam.ApplicationIdentity(r.app.ID), group, ident.Perm("org:catalog:read"))
		require.NoError(t, err)
		return ok
	}
	for _, r := range []registered{removedApp, bannedApp, ownerApp} {
		require.True(t, canRead(r), "control: an application works while its registrar does")
	}

	t.Run("an API key registers no application", func(t *testing.T) {
		key := h.issue(base+"/api-keys", ownerToken, map[string]any{"name": "ci", "role": "org:manager"})
		_, err := h.upsertGroupApp(iam.APIKeyIdentity(key.ID), group, "https://"+unique("keyapp")+".security.test", publicKeyPEM(t), true)
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	})
	t.Run("an application never outranks its registrar", func(t *testing.T) {
		requireRefused(t, setRole(h.auth, ctx, iam.UserIdentity(owner.id), group, iam.RemoteApplicationSubject(removedApp.app.ID), orgPersona.OwnerRole()))
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
			resp := h.do(request{method: http.MethodDelete, path: base + "/members/users/" + a.id, token: ownerToken})
			require.Less(t, resp.status, 300, resp.String())
		}},
		{"the registrar is banned", bannedApp, func(a account) {
			require.NoError(t, h.auth.Ban(ctx, iam.SystemIdentity(), a.id, iam.Ban{Reason: "abuse"}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.end(tc.app.registrar)
			roles, err := h.auth.GroupRoles(ctx, group, []iam.Subject{iam.RemoteApplicationSubject(tc.app.app.ID)})
			require.NoError(t, err)
			require.Empty(t, roles, "the application kept its role past its registrar's authority")
			require.False(t, canRead(tc.app))
		})
	}
	t.Run("control: another registrar's application survives a manager's removal", func(t *testing.T) {
		resp := h.do(request{method: http.MethodDelete, path: base + "/members/users/" + bystander.id, token: ownerToken})
		require.Less(t, resp.status, 300, resp.String())
		require.True(t, canRead(ownerApp))
	})
}

// TestSecurityTokenMatrix: across token types, subject claims, issuers and
// sender binding, only a user's access token verifies, and only this
// deployment's grants AuthKit authority. A delegated, remote-application or
// service token, even signed with this deployment's key or a registered
// application's, verifies nowhere.
func TestSecurityTokenMatrix(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	user := h.newAccount("matrixuser")
	h.grant(iam.RootGroup(), user, "admin")
	managed, foreign := newSigner(t, "managed-kid"), newSigner(t, "foreign-kid")
	const managedIssuer, foreignIssuer = "https://managed.security.test", "https://foreign.security.test"
	_, err := h.auth.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.RootGroup(), iam.RemoteApplication{
		Issuer: managedIssuer, PublicKeys: staticKeys(t, managed), Enabled: true,
	})
	require.NoError(t, err)
	// The Client authenticates only its own tokens; another issuer's,
	// registered or not, are a host verifier's.
	foreignVerifier := verify.NewVerifier()
	require.NoError(t, foreignVerifier.AddIssuer(foreignIssuer, []string{audience}, verify.IssuerOptions{Keys: []iam.RemoteApplicationKey{{KID: foreign.KID(), PublicKeyPEM: pemOf(t, foreign.Public())}}}))
	authenticators := map[string]verify.Authenticator{"local": h.auth, "managed": h.auth, "foreign": foreignVerifier}
	leafDER, err := base64.RawURLEncoding.DecodeString(delegateCertificate(t))
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	issuers := []struct {
		name, iss string
		signer    keys.Signer
	}{{"local", issuer, signer()}, {"managed", managedIssuer, managed}, {"foreign", foreignIssuer, foreign}}
	typs := []string{jose.AccessTokenType, "delegated-access+jwt", "remote-application-access+jwt", "service+jwt", ""}
	subjects := []string{"sub", "delegated_sub", "both", "none"}
	allowed := map[[3]string]bool{
		{"local", jose.AccessTokenType, "sub"}:    true,
		{"local", jose.AccessTokenType, "both"}:   true,
		{"foreign", jose.AccessTokenType, "sub"}:  true,
		{"foreign", jose.AccessTokenType, "both"}: true,
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
						claims["permissions"] = []string{ident.RootUsersRead.String()}
					}
					if bound {
						claims[jose.ConfirmationClaim] = map[string]any{jose.CertificateThumbprintMember: jose.CertificateThumbprint(leaf.Raw)}
					}
					token, err := jose.Sign(ctx, is.signer, typ, claims)
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
					cl, err := authenticators[is.name].VerifyRequest(req)
					if !allowed[[3]string{is.name, typ, subject}] || bound {
						require.Error(t, err, name)
						if is.name != "foreign" {
							require.Equal(t, http.StatusUnauthorized, h.get("/admin/users", token).status, name)
						}
						continue
					}
					require.NoError(t, err, name)
					who, _ := gateIdentity(authenticators[is.name], req)
					state, ok := iam.StateOf(who)
					require.False(t, state.IsSystem(), name)
					if is.name == "local" {
						require.Empty(t, cl.Permissions, "a native token carries no grant: %s", name)
						require.True(t, ok && state.IsUser(), name)
						require.Equal(t, user.id, state.ID(), name)
					} else {
						require.False(t, ok, "a foreign user has no AuthKit authority: %s", name)
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
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner := h.newAccount("pageowner")
	group, _ := h.newOrg(owner)
	for _, slug := range []string{"page-a", "page-b", "page-c"} {
		_, err := h.auth.UpsertRemoteApplication(ctx, iam.UserIdentity(owner.id), group, iam.RemoteApplication{
			Issuer: "https://" + slug + ".security.test", PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: publicKeyPEM(t)}}, Enabled: true,
		})
		require.NoError(t, err)
	}
	first, err := h.auth.ListRemoteApplications(ctx, group, iam.PageRequest{Limit: 2})
	require.NoError(t, err)
	require.Len(t, first.Items, 2)
	require.NotEmpty(t, first.Next)
	second, err := h.auth.ListRemoteApplications(ctx, group, iam.PageRequest{Cursor: first.Next, Limit: 2})
	require.NoError(t, err)
	require.Len(t, second.Items, 1)
	require.Empty(t, second.Next)
	var issuers []string
	for _, a := range append(first.Items, second.Items...) {
		issuers = append(issuers, a.Issuer)
	}
	require.Equal(t, []string{"https://page-c.security.test", "https://page-b.security.test", "https://page-a.security.test"}, issuers, "newest first, no repeats")
	_, err = h.auth.ListRemoteApplications(ctx, group, iam.PageRequest{Cursor: "not-a-cursor"})
	require.Error(t, err)
}

// TestSecurityRemovedRoutesAreGone: v1 serves no signed-document,
// application self-registration, remote-application, delegated-token or
// custom-role route, nor
// the member, invite-link and root-role routes the member and invitation
// resources replaced, even with every capability on. The catalog lists none,
// and a signed-in owner gets 404 (405 where the path serves another method).
// The Go operations on applications remain.
func TestSecurityRemovedRoutesAreGone(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withApps))
	ctx := context.Background()
	owner := h.newAccount("cutowner")
	group, base := h.newOrg(owner)
	token := h.login(owner).AccessToken
	app := h.registerApp(group, owner, "cut-app", "member")

	for _, pattern := range patterns(h.auth) {
		for _, gone := range []string{"/.well-known/authkit/", "/applications/", "/remote-applications", "/delegated/"} {
			require.NotContains(t, pattern, gone)
		}
	}
	require.NotContains(t, patterns(h.auth), "POST "+apiPrefix+"/groups/{group_id}/roles")
	require.Contains(t, patterns(h.auth), "GET "+apiPrefix+"/groups/{group_id}/roles", "control: the role list stays")

	for _, tc := range []struct {
		req    request
		status int
	}{
		{request{method: http.MethodGet, path: "//.well-known/authkit/documents/sha256:" + strings.Repeat("0", 64), token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/delegated/token", token: token, body: map[string]any{"requested_grant": map[string]any{}}}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/applications/register", body: map[string]string{"domain": "cut.security.test"}}, http.StatusNotFound},
		{request{method: http.MethodGet, path: base + "/remote-applications", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/remote-applications", token: token,
			body: map[string]any{"slug": "cut-new", "issuer": "https://cut-new.security.test", "public_keys": []map[string]string{{"public_key_pem": publicKeyPEM(t)}}}}, http.StatusNotFound},
		{request{method: http.MethodDelete, path: base + "/remote-applications/cut-app", token: token}, http.StatusNotFound},
		{request{method: http.MethodPut, path: base + "/remote-applications/cut-app/roles/org:owner", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/roles", token: token,
			body: map[string]any{"role": "curator", "permissions": []string{"org:catalog:read"}}}, http.StatusMethodNotAllowed},
		{request{method: http.MethodDelete, path: base + "/roles/org:member", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/members", token: token, body: map[string]string{"user_id": owner.id, "role": "org:member"}}, http.StatusMethodNotAllowed},
		{request{method: http.MethodPut, path: base + "/members/" + owner.id + "/roles/org:member", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: base + "/invites/links", token: token, body: map[string]string{"role": "org:member"}}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/invites/redeem", token: token, body: map[string]string{"code": "x"}}, http.StatusNotFound},
		{request{method: http.MethodGet, path: "/admin/roles", token: token}, http.StatusNotFound},
		{request{method: http.MethodPut, path: "/admin/users/" + owner.id + "/roles/root:owner", token: token}, http.StatusNotFound},
		{request{method: http.MethodGet, path: "/admin/users/" + owner.id + "/signins", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/admin/users/" + owner.id + "/ban", token: token, body: map[string]string{"until": "infinite"}}, http.StatusMethodNotAllowed},
		{request{method: http.MethodPost, path: "/admin/users/" + owner.id + "/unban", token: token}, http.StatusNotFound},
		{request{method: http.MethodPost, path: "/admin/users/" + owner.id + "/sessions/revoke", token: token}, http.StatusNotFound},
	} {
		resp := h.do(tc.req)
		require.Equal(t, tc.status, resp.status, "%s %s: %s", tc.req.method, tc.req.path, resp)
	}

	stored, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer(app.Issuer))
	require.NoError(t, err)
	require.True(t, stored.Enabled, "the application is untouched")
	require.Equal(t, h.role(orgPersona, "member"), h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
	_, err = h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://cut-new.security.test"))
	require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound)
	require.Equal(t, http.StatusOK, h.get(base+"/roles", token).status, "control: the role list stays")
}
