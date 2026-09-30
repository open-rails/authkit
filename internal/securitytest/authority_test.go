package securitytest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/provider"
	"github.com/stretchr/testify/require"
)

var orgPersona = ident.Persona("org")

// securityModel is the permission model most security tests run: an org
// persona with every capability, and a spread of root and org roles.
type securityModel struct {
	*authkit.Roles
	org         *authkit.PersonaDef
	catalogRead iam.Perm
}

func newSecurityModel(root ...authkit.PersonaOption) securityModel {
	r := authkit.NewRoles(root...)
	users := r.Root.Users
	r.Root.Role("superadmin", users.Read, users.Ban, users.Delete, users.Manage, users.Invite)
	r.Root.Role("moderator", users.Ban)
	r.Root.Role("admin", users.Ban, users.Manage, users.Read)
	org := r.Persona("org", authkit.RemoteApplications, authkit.APIKeys)
	catalogRead := org.Permission("catalog", "read")
	org.Permission("settings", "edit")
	org.Role("member", catalogRead)
	memberAdmin := org.Role("member-admin", org.Members.Manage, org.Members.Read)
	credentialAdmin := org.Role("credential-admin", org.Credentials.All())
	org.Role("manager", catalogRead, memberAdmin, credentialAdmin)
	return securityModel{Roles: r, org: org, catalogRead: catalogRead}
}

func withRBAC(c *authkit.Config) { c.Roles = newSecurityModel().Roles }

// grant assigns the role name of group's persona with system authority. The
// holder of an MFA-required role enrolls the email second factor first.
func (h *host) grant(group iam.GroupRef, a account, name string) {
	h.t.Helper()
	err := setRole(h.auth, h.t.Context(), iam.SystemActor(), group, iam.UserSubject(a.id), roleIn(h.t, h.auth, group, name))
	if errors.Is(err, iam.ErrSubjectMFARequired) {
		h.enrollEmail2FA(a)
		grantRole(h.t, h.auth, group, iam.UserSubject(a.id), name)
		return
	}
	require.NoError(h.t, err)
}

func publicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestSecurityUnbanRequiresAuthority: lifting a ban restores authority, so it
// needs the same no-escalation check as imposing one, and never applies to the
// actor's own account.
func TestSecurityUnbanRequiresAuthority(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	root := iam.RootGroup()
	owner, admin := h.newAccount("owner"), h.newAccount("admin")
	moderator, peer := h.newAccount("moderator"), h.newAccount("peermod")
	h.grant(root, owner, "superadmin") // the root owner role requires MFA
	h.grant(root, admin, "admin")
	h.grant(root, moderator, "moderator")
	h.grant(root, peer, "moderator")
	ownerToken := h.login(owner).AccessToken
	moderatorToken := h.login(moderator).AccessToken
	peerToken := h.login(peer).AccessToken
	unban := func(target account, token string) response {
		return h.post("/admin/users/"+target.id+"/unban", nil, token)
	}
	require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), moderator.id, iam.Ban{}))
	require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), admin.id, iam.Ban{}))

	for _, tc := range []struct {
		name   string
		target account
		token  string
		status int // the ban ended the moderator's own session
	}{
		{"banned moderator lifts own ban with a pre-ban token", moderator, moderatorToken, http.StatusUnauthorized},
		{"moderator lifts the ban of a more privileged admin", admin, peerToken, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := unban(tc.target, tc.token)
			require.Equal(t, tc.status, resp.status, resp.String())
			u, err := h.auth.User(ctx, iam.UserByID(tc.target.id), authkit.IncludeDeleted())
			require.NoError(t, err)
			require.NotNil(t, u.Ban, "ban was lifted")
		})
	}
	t.Run("control: owner lifts both bans", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, unban(moderator, ownerToken).status)
		require.Equal(t, http.StatusNoContent, unban(admin, ownerToken).status)
		h.login(moderator)
	})
}

// TestSecurityRemoteApplicationTakeover: an application's keys are its
// authority. A bounded credentials manager must not swap the keys of, disable
// or delete an application holding a role above their own.
func TestSecurityRemoteApplicationTakeover(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner, manager := h.newAccount("orgowner"), h.newAccount("orgmanager")
	group, err := h.createOrg(ctx, owner)
	require.NoError(t, err)
	h.grant(group, manager, "manager")
	ownerActor, managerActor := iam.UserActor(owner.id), iam.UserActor(manager.id)
	register := func(actor iam.Actor, issuer, key string, enabled bool) error {
		_, err := h.upsertGroupApp(actor, group, issuer, key, enabled)
		return err
	}
	ownedKey := publicKeyPEM(t)
	require.NoError(t, register(ownerActor, "https://owner-app.security.test", ownedKey, true))
	ownerApp, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://owner-app.security.test"))
	require.NoError(t, err)
	grantRole(t, h.auth, group, iam.RemoteApplicationSubject(ownerApp.ID), "owner")

	for _, tc := range []struct {
		name   string
		attack func() error
	}{
		{"swap the owner application's keys", func() error {
			return register(managerActor, "https://owner-app.security.test", publicKeyPEM(t), true)
		}},
		{"disable the owner application", func() error {
			return register(managerActor, "https://owner-app.security.test", ownedKey, false)
		}},
		{"delete the owner application", func() error {
			return h.auth.DeleteRemoteApplication(ctx, managerActor, group, ownerApp.ID)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireRefused(t, tc.attack())
			app, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://owner-app.security.test"))
			require.NoError(t, err)
			require.True(t, app.Enabled)
			require.Len(t, app.PublicKeys, 1)
			require.Equal(t, ownedKey, app.PublicKeys[0].PublicKeyPEM)
		})
	}
	t.Run("control: manager operates an application within their authority", func(t *testing.T) {
		require.NoError(t, register(managerActor, "https://member-app.security.test", publicKeyPEM(t), true))
		require.NoError(t, register(managerActor, "https://member-app.security.test", publicKeyPEM(t), true))
		memberApp, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer("https://member-app.security.test"))
		require.NoError(t, err)
		require.NoError(t, h.auth.DeleteRemoteApplication(ctx, managerActor, group, memberApp.ID))
	})
	t.Run("control: owner rotates the owner application's keys", func(t *testing.T) {
		require.NoError(t, register(ownerActor, "https://owner-app.security.test", publicKeyPEM(t), true))
	})
}

// TestSecurityRoleEscalation keeps the no-escalation rules for direct grants,
// invite links and API keys under the embedded HTTP surface.
func TestSecurityRoleEscalation(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	owner, manager, member := h.newAccount("escowner"), h.newAccount("escmanager"), h.newAccount("escmember")
	group, err := h.createOrg(ctx, owner)
	require.NoError(t, err)
	other, err := h.createOrg(ctx, owner)
	require.NoError(t, err)
	h.grant(group, manager, "manager")
	h.grant(group, member, "member")
	managerToken := h.login(manager).AccessToken
	memberToken := h.login(member).AccessToken
	base := "/groups/" + group.ID()

	for _, tc := range []struct {
		name  string
		req   request
		allow bool
	}{
		{"manager grants themself owner", request{method: http.MethodPut, path: base + "/members/" + manager.id + "/roles/org:owner", token: managerToken}, false},
		{"manager grants a member owner", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/org:owner", token: managerToken}, false},
		{"manager demotes the owner", request{method: http.MethodPut, path: base + "/members/" + owner.id + "/roles/org:member", token: managerToken}, false},
		{"manager removes the owner", request{method: http.MethodDelete, path: base + "/members/" + owner.id, token: managerToken}, false},
		{"manager mints an owner invite link", request{method: http.MethodPost, path: base + "/invites/links", token: managerToken,
			body: map[string]any{"role": "org:owner"}}, false},
		{"manager mints an owner API key", request{method: http.MethodPost, path: base + "/api-keys", token: managerToken,
			body: map[string]any{"name": "k", "role": "org:owner"}}, false},
		{"member grants themself manager", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/org:manager", token: memberToken}, false},
		{"manager acts on a group they do not belong to", request{method: http.MethodPut, path: "/groups/" + other.ID() + "/members/" + member.id + "/roles/org:member", token: managerToken}, false},
		{"root admin surface with a group role", request{method: http.MethodGet, path: "/admin/users", token: managerToken}, false},
		{"control: manager assigns member", request{method: http.MethodPut, path: base + "/members/" + member.id + "/roles/org:member", token: managerToken}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.do(tc.req)
			if tc.allow {
				require.Less(t, resp.status, 300, resp.String())
				return
			}
			require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity}, resp.status, resp.String())
		})
	}
	ownerAllowed, err := h.auth.Can(ctx, iam.UserActor(manager.id), group, ownerOnly)
	require.NoError(t, err)
	require.False(t, ownerAllowed)
	stillOwner, err := h.auth.Can(ctx, iam.UserActor(owner.id), group, ident.Perm("org:members:manage"))
	require.NoError(t, err)
	require.True(t, stillOwner)
}

// ownerOnly is an org permission only the owner (org:*) holds.
var ownerOnly = ident.Perm("org:settings:edit")

// createOrg creates an org owned by owner, as the host does.
func (h *host) createOrg(ctx context.Context, owner account) (iam.GroupRef, error) {
	o := iam.UserSubject(owner.id)
	g, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona, Owner: &o})
	return iam.GroupByID(g.ID), err
}

// newOrg creates an org whose founder is its owner, and its route base.
func (h *host) newOrg(founder account) (iam.GroupRef, string) {
	h.t.Helper()
	group, err := h.createOrg(context.Background(), founder)
	require.NoError(h.t, err)
	return group, "/groups/" + group.ID()
}

// issued is a created API key or invitation: its id, and its secret or code
// shown once.
type issued struct {
	ID     string
	Code   string
	Secret string
}

func (h *host) issue(path, token string, body map[string]any) issued {
	h.t.Helper()
	resp := h.post(path, body, token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
	var created struct {
		APIKey     struct{ ID string } `json:"api_key"`
		Invitation struct{ ID string } `json:"invitation"`
		Code       string              `json:"code"`
		Secret     string              `json:"secret"`
	}
	resp.json(h.t, &created)
	out := issued{ID: created.APIKey.ID + created.Invitation.ID, Code: created.Code, Secret: created.Secret}
	require.NotEmpty(h.t, out.ID)
	return out
}

func liveKey(t *testing.T, h *host, group iam.GroupRef, id string) bool {
	t.Helper()
	keys, err := h.auth.ListAPIKeys(context.Background(), group, iam.PageRequest{Limit: iam.MaxPageLimit})
	require.NoError(t, err)
	for _, k := range keys.Items {
		if k.ID == id {
			return k.RevokedAt == nil
		}
	}
	t.Fatalf("API key %s not found", id)
	return false
}

func liveLink(t *testing.T, h *host, group iam.GroupRef, id string) bool {
	t.Helper()
	links, err := h.auth.ListInvitations(context.Background(), group, iam.PageRequest{Limit: iam.MaxPageLimit})
	require.NoError(t, err)
	for _, l := range links.Items {
		if l.ID == id {
			return l.RevokedAt == nil
		}
	}
	t.Fatalf("invite link %s not found", id)
	return false
}

// TestSecurityDemotedCreatorCredentials: an invite link or API key never
// outlives its creator's authority. A demoted owner must not redeem their own
// owner link, or keep an owner key, to get the role back.
func TestSecurityDemotedCreatorCredentials(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	founder, creator := h.newAccount("founder"), h.newAccount("creator")
	group, base := h.newOrg(founder)
	h.grant(group, creator, "owner")
	creatorToken, founderToken := h.login(creator).AccessToken, h.login(founder).AccessToken
	link := h.issue(base+"/invites/links", creatorToken, map[string]any{"role": "org:owner"})
	key := h.issue(base+"/api-keys", creatorToken, map[string]any{"name": "creator-key", "role": "org:owner"})
	founderKey := h.issue(base+"/api-keys", founderToken, map[string]any{"name": "founder-key", "role": "org:owner"})
	memberKey := h.issue(base+"/api-keys", creatorToken, map[string]any{"name": "member-key", "role": "org:member"})
	resp := h.do(request{method: http.MethodPut, path: base + "/members/" + creator.id + "/roles/org:manager", token: founderToken})
	require.Less(t, resp.status, 300, resp.String())

	t.Run("demoted creator redeems their own owner link", func(t *testing.T) {
		resp := h.post("/invites/redeem", map[string]string{"code": link.Code}, h.login(creator).AccessToken)
		require.GreaterOrEqual(t, resp.status, 400, resp.String())
		owner, err := h.auth.Can(ctx, iam.UserActor(creator.id), group, ownerOnly)
		require.NoError(t, err)
		require.False(t, owner, "the demoted creator regained owner")
		require.False(t, liveLink(t, h, group, link.ID))
	})
	t.Run("demoted creator's owner API key", func(t *testing.T) {
		require.False(t, liveKey(t, h, group, key.ID))
	})
	t.Run("control: credentials the creator can still issue survive", func(t *testing.T) {
		require.True(t, liveKey(t, h, group, memberKey.ID))
		require.True(t, liveKey(t, h, group, founderKey.ID))
	})
}

// TestSecurityRevokeAboveOwnRole: revoking a credential is the authority to
// issue it; a bounded manager cannot revoke the owner's key or invite link.
func TestSecurityRevokeAboveOwnRole(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	owner, manager := h.newAccount("revowner"), h.newAccount("revmanager")
	group, base := h.newOrg(owner)
	h.grant(group, manager, "manager")
	ownerToken, managerToken := h.login(owner).AccessToken, h.login(manager).AccessToken
	ownerKey := h.issue(base+"/api-keys", ownerToken, map[string]any{"name": "owner-key", "role": "org:owner"})
	ownerLink := h.issue(base+"/invites/links", ownerToken, map[string]any{"role": "org:owner"})
	remove := func(path string) response {
		return h.do(request{method: http.MethodDelete, path: path, token: managerToken})
	}
	resp := remove(base + "/api-keys/" + ownerKey.ID)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.True(t, liveKey(t, h, group, ownerKey.ID))
	resp = remove(base + "/invites/links/" + ownerLink.ID)
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	require.True(t, liveLink(t, h, group, ownerLink.ID))

	t.Run("control: manager revokes what they could issue", func(t *testing.T) {
		key := h.issue(base+"/api-keys", managerToken, map[string]any{"name": "member-key", "role": "org:member"})
		link := h.issue(base+"/invites/links", managerToken, map[string]any{"role": "org:member"})
		require.Equal(t, http.StatusNoContent, remove(base+"/api-keys/"+key.ID).status)
		require.Equal(t, http.StatusNoContent, remove(base+"/invites/links/"+link.ID).status)
		require.False(t, liveKey(t, h, group, key.ID))
		require.False(t, liveLink(t, h, group, link.ID))
	})
}

// TestSecurityRemoteApplicationIssuerSquat: a group must not bind this
// deployment's own or its identity providers' issuers, nor an issuer another
// group already holds.
func TestSecurityRemoteApplicationIssuerSquat(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithDeps(func(d *authkit.Deps) {
		d.Providers = []provider.Provider{provider.GitHub("squat-client", "squat-secret")}
	}))
	squatter := h.newAccount("squatter")
	group, _ := h.newOrg(squatter)
	register := func(actor account, group iam.GroupRef, iss string) error {
		_, err := h.upsertGroupApp(iam.UserActor(actor.id), group, iss, publicKeyPEM(t), true)
		return err
	}
	for _, reserved := range []string{issuer + "/", strings.ToUpper(issuer), "https://github.com/login/oauth"} {
		require.ErrorIs(t, register(squatter, group, reserved), iam.ErrReservedIssuer, reserved)
	}

	const victimIssuer = "https://victim-app.security.test"
	require.NoError(t, register(squatter, group, victimIssuer))
	rival := h.newAccount("squatrival")
	rivalGroup, _ := h.newOrg(rival)
	require.ErrorIs(t, register(rival, rivalGroup, victimIssuer), iam.ErrRemoteApplicationIssuerConflict)
}

// TestSecurityAccountPeerRemoteApplication: a deployment sharing this account
// store delegates its users here as a system-registered remote application.
// Its delegated subjects name accounts in the shared store, so no group may
// register its issuer; its native user tokens, signed by the same
// keys, never authenticate here in either role; and registering it never
// shadows this deployment's own issuer.
func TestSecurityAccountPeerRemoteApplication(t *testing.T) {
	const peerIssuer = "https://peer.security.test"
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(func(c *authkit.Config) {
		c.Token.AccountIssuers = []string{issuer, peerIssuer}
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Providers = []provider.Provider{provider.GitHub("peer-client", "peer-secret")}
	}))
	ctx := context.Background()
	peerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)
	peerPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	keys := []iam.RemoteApplicationKey{{KID: "peer-kid", PublicKeyPEM: peerPEM}}

	t.Run("no group may claim the peer issuer", func(t *testing.T) {
		squatter := h.newAccount("peersquatter")
		group, _ := h.newOrg(squatter)
		for _, iss := range []string{peerIssuer, strings.ToUpper(peerIssuer) + "/"} {
			_, err := h.upsertGroupApp(iam.UserActor(squatter.id), group, iss, publicKeyPEM(t), true)
			require.ErrorIs(t, err, iam.ErrReservedIssuer, iss)
		}
		_, err = h.auth.RemoteApplication(ctx, iam.AppByIssuer(peerIssuer))
		require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound)
	})

	t.Run("the system may not register this deployment's or a provider's issuer", func(t *testing.T) {
		for _, iss := range []string{issuer, "https://github.com/login/oauth"} {
			enabled := true
			_, err := h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{
				{Issuer: iss, PublicKeys: []iam.RemoteApplicationKey{{PublicKeyPEM: publicKeyPEM(t)}}, Enabled: &enabled},
			}}, iam.BootstrapOptions{})
			require.ErrorIs(t, err, iam.ErrReservedIssuer, iss)
		}
	})

	enabled := true
	_, err = h.auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{
		{Issuer: peerIssuer, PublicKeys: keys, Enabled: &enabled},
	}}, iam.BootstrapOptions{})
	require.NoError(t, err)

	user := h.newAccount("peeruser")
	ver := h.auth
	peerToken := func(typ string, claims jwt.MapClaims) string {
		now := time.Now()
		claims["iss"], claims["iat"], claims["exp"] = peerIssuer, now.Unix(), now.Add(5*time.Minute).Unix()
		return sign(t, jwt.SigningMethodRS256, peerKey, map[string]any{"kid": "peer-kid", "typ": typ}, claims)
	}
	delegated := peerToken(jose.DelegatedAccessTokenType, jwt.MapClaims{"aud": []string{audience}, "delegated_sub": user.id})

	t.Run("the peer delegates a shared account", func(t *testing.T) {
		cl, err := ver.Verify(ctx, delegated)
		require.NoError(t, err)
		require.Equal(t, peerIssuer, cl.Issuer)
		require.Equal(t, user.id, cl.DelegatedSubject)
		require.Empty(t, cl.UserID)
		require.NotEmpty(t, cl.RemoteApplicationID)
	})

	t.Run("a peer user token is not a delegation or a local session", func(t *testing.T) {
		for name, aud := range map[string][]string{"peer audience": {"peer-app"}, "this audience": {audience}} {
			_, err := ver.Verify(ctx, peerToken(jose.AccessTokenType, jwt.MapClaims{"aud": aud, "sub": user.id, "sid": "peer-session"}))
			require.Error(t, err, name)
			require.Equal(t, http.StatusUnauthorized, h.get("/me", peerToken(jose.AccessTokenType, jwt.MapClaims{"aud": aud, "sub": user.id})).status, name)
		}
		_, err := ver.Verify(ctx, peerToken(jose.DelegatedAccessTokenType, jwt.MapClaims{"aud": []string{"peer-app"}, "delegated_sub": user.id}))
		require.Error(t, err, "a delegation for another audience")
	})

	t.Run("the peer registration never shadows this deployment's issuer", func(t *testing.T) {
		require.Equal(t, http.StatusOK, h.get("/me", h.login(user).AccessToken).status)
		forged := sign(t, jwt.SigningMethodRS256, peerKey, map[string]any{"kid": signer().KID(), "typ": jose.AccessTokenType},
			jwt.MapClaims{"iss": issuer, "aud": []string{audience}, "sub": user.id, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
		require.Equal(t, http.StatusUnauthorized, h.get("/me", forged).status)
	})

	t.Run("the system disables the peer", func(t *testing.T) {
		app, err := h.auth.RemoteApplication(ctx, iam.AppByIssuer(peerIssuer))
		require.NoError(t, err)
		app.Enabled = false
		_, err = h.auth.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.RootGroup(), app)
		require.NoError(t, err)
		_, err = ver.Verify(ctx, delegated)
		require.Error(t, err)
	})
}

// TestSecurityGroupRoleIDsAreCanonical (P4): an upper-case subject id names
// the same account in group role operations. A manager who leaves a group
// under an upper-case id takes the API keys, invite links and application
// roles they issued there with them.
func TestSecurityGroupRoleIDsAreCanonical(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	founder, manager := h.newAccount("p4founder"), h.newAccount("p4manager")
	group, base := h.newOrg(founder)
	h.grant(group, manager, "manager")
	token := h.login(manager).AccessToken
	key := h.issue(base+"/api-keys", token, map[string]any{"name": "ci", "role": "org:member"})
	link := h.issue(base+"/invites/links", token, map[string]any{"role": "org:member"})
	app := h.registerApp(group, manager, "p4-app", "member")
	founderKey := h.issue(base+"/api-keys", h.login(founder).AccessToken, map[string]any{"name": "founder", "role": "org:member"})

	resp := h.do(request{method: http.MethodDelete, path: base + "/members/" + strings.ToUpper(manager.id), token: token})
	require.Less(t, resp.status, 300, resp.String())
	require.Empty(t, h.roleOf(group, iam.UserSubject(manager.id)), "control: the membership is gone")
	require.False(t, liveKey(t, h, group, key.ID), "the API key outlived its issuer's membership")
	require.False(t, liveLink(t, h, group, link.ID), "the invite link outlived its issuer's membership")
	require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)), "the application kept its role")

	t.Run("control: other issuers' credentials survive", func(t *testing.T) {
		require.True(t, liveKey(t, h, group, founderKey.ID))
	})
}

// ownerlessGroups pages through the ownerless groups one group at a time.
func (h *host) ownerlessGroups() []string {
	h.t.Helper()
	var ids []string
	q := iam.GroupQuery{Ownerless: true, Page: iam.PageRequest{Limit: 1}}
	for {
		out, err := h.auth.ListGroups(context.Background(), q)
		require.NoError(h.t, err)
		for _, g := range out.Items {
			ids = append(ids, g.ID)
		}
		if out.Next == "" {
			return ids
		}
		q.Page.Cursor = out.Next
	}
}

// TestSecurityOwnApplicationIsNoReplacementOwner (R1): an application a user
// registered never stands in for that user as a group's owner, since its
// authority ends with theirs. The last human owner cannot delete themselves,
// be deleted or be banned while only their own application co-owns the
// group; ListGroups with GroupQuery.Ownerless lists groups that have no owner.
func TestSecurityOwnApplicationIsNoReplacementOwner(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC))
	ctx := context.Background()
	founder := h.newAccount("r1founder")
	group, _ := h.newOrg(founder)
	g, err := h.auth.Group(ctx, group)
	require.NoError(t, err)
	token := h.login(founder).AccessToken
	app := h.registerApp(group, founder, "r1-app", "owner")

	resp := h.do(request{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: token})
	require.Equal(t, http.StatusConflict, resp.status, "the last human owner deleted itself: %s", resp)
	require.Equal(t, "last_owner", resp.errorCode())
	require.ErrorIs(t, opErr(h.auth.DeleteUsers(ctx, iam.SystemActor(), []string{founder.id})), iam.ErrLastOwner)
	require.ErrorIs(t, h.auth.Ban(ctx, iam.SystemActor(), founder.id, iam.Ban{Reason: "r1"}), iam.ErrLastOwner)
	require.Equal(t, orgPersona.OwnerRole(), h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
	require.NotContains(t, h.ownerlessGroups(), g.ID)

	t.Run("Ownerless lists groups without an owner", func(t *testing.T) {
		var empty []string
		for range 2 {
			created, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona})
			require.NoError(t, err)
			empty = append(empty, created.ID)
		}
		require.Subset(t, h.ownerlessGroups(), empty)
		grantRole(t, h.auth, iam.GroupByID(empty[0]), iam.UserSubject(h.newAccount("r1adopter").id), "owner")
		require.NotContains(t, h.ownerlessGroups(), empty[0])
		require.Contains(t, h.ownerlessGroups(), empty[1])
	})
	t.Run("control: with a second owner the founder leaves and its application's role goes", func(t *testing.T) {
		h.grant(group, h.newAccount("r1second"), "owner")
		resp := h.do(request{method: http.MethodDelete, path: "/user", body: map[string]string{"password": password}, token: token})
		require.Equal(t, http.StatusNoContent, resp.status, resp.String())
		require.Empty(t, h.roleOf(group, iam.RemoteApplicationSubject(app.ID)))
		require.NotContains(t, h.ownerlessGroups(), g.ID)
	})
}
