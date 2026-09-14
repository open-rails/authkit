package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// Audit regression: an application signing identity must not name local users.
func TestV1AuditRemoteIssuerCannotImpersonateLocalUser(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newScopeBindingCore(t, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	user, err := core.CreateUser(ctx, "audit-victim@example.test", "audit-victim")
	require.NoError(t, err)
	gid := createRepoGroup(t, ctx, core, pg.Pool, "audit-attacker")
	signer, err := jwtkit.NewRSASigner(2048, "audit-attacker-kid")
	require.NoError(t, err)
	issuer := "https://audit-attacker.example"
	app, err := core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug: "audit-attacker", PermissionGroupID: gid, Issuer: issuer, Enabled: true,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	authority, err := core.ResolveRemoteApplicationAuthority(ctx, app.ID)
	require.NoError(t, err)
	require.Empty(t, authority.Permissions, "the app has no assigned authority")
	token := mintAccessJWT(t, signer, issuer, map[string]any{
		"aud": "test-app", "sub": user.ID, "auth_time": time.Now().Unix(), "amr": []string{"pwd", "otp"}, "mfa_enrolled": true,
	})
	h, err := MountHandler(srv, MountOptions{APIPrefix: "/api/v1"})
	require.NoError(t, err)
	for _, disabled := range []bool{false, true} {
		if disabled {
			app.Enabled = false
			_, err = core.UpsertRemoteApplication(ctx, *app)
			require.NoError(t, err)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		t.Logf("remote app disabled=%v HTTP=%d body=%s", disabled, w.Code, w.Body.String())
		if w.Code == http.StatusOK {
			t.Errorf("unprivileged remote signer impersonated local victim (disabled=%v)", disabled)
		}
	}
}

// Audit regression: every delegated verifier must enforce revocation/ceiling,
// including the documented resource-server entrypoint and its request form.
func TestV1AuditDelegatedVerifiersRejectDisabledIssuer(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newScopeBindingCore(t, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	gid := createRepoGroup(t, ctx, core, pg.Pool, "audit-delegate")
	signer, err := jwtkit.NewRSASigner(2048, "audit-delegate-kid")
	require.NoError(t, err)
	issuer := "https://audit-delegate.example"
	app, err := core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug: "audit-delegate", PermissionGroupID: gid, Issuer: issuer, Enabled: true,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	})
	require.NoError(t, err)
	require.NoError(t, core.AssignRemoteApplicationRole(ctx, app.ID, "deployer"))
	mint := func(perms []string) string {
		tok, err := embedded.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
			Issuer: issuer, Audiences: []string{"test-app"}, DelegatedSubject: "external-user", Permissions: perms, TTL: time.Minute,
		})
		require.NoError(t, err)
		return tok
	}
	good := mint([]string{"repo:models:deploy"})
	_, _, err = srv.Verifier().VerifyDelegatedAccess(ctx, good)
	require.NoError(t, err)
	malicious := mint([]string{"root:*"})
	_, _, err = srv.Verifier().VerifyDelegatedAccess(ctx, malicious)
	require.Error(t, err, "enabled app must respect its authority ceiling")
	app.Enabled = false
	_, err = core.UpsertRemoteApplication(ctx, *app)
	require.NoError(t, err)
	for name, token := range map[string]string{"original authority": good, "root escalation": malicious} {
		_, _, err = srv.Verifier().VerifyDelegatedAccess(ctx, token)
		if err == nil {
			t.Errorf("VerifyDelegatedAccess accepts disabled issuer: %s", name)
		}
		r := httptest.NewRequest(http.MethodGet, "https://resource.example/download", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		cl, _, err := srv.Verifier().VerifyDelegatedAccessRequest(r)
		if err == nil {
			t.Errorf("VerifyDelegatedAccessRequest accepts disabled issuer %s; permissions=%v", name, cl.Permissions)
		}
		_, err = srv.Verifier().VerifyRequest(r)
		require.Error(t, err, fmt.Sprintf("normal request rejects disabled issuer %s", name))
	}
}

// Audit regression: changing a machine token to delegated may only narrow its authority.
func TestV1AuditDelegatedIssuerPreservesGroupScope(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newScopeBindingCore(t, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	alpha := createRepoGroup(t, ctx, core, pg.Pool, "audit-alpha")
	beta := createRepoGroup(t, ctx, core, pg.Pool, "audit-beta")
	signer, err := jwtkit.NewRSASigner(2048, "audit-scope-kid")
	require.NoError(t, err)
	issuer := "https://audit-scope.example"
	app, err := core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{Slug: "audit-scope", PermissionGroupID: alpha, Issuer: issuer, Enabled: true, PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}}})
	require.NoError(t, err)
	require.NoError(t, core.AssignRemoteApplicationRole(ctx, app.ID, "deployer"))
	self, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{Issuer: issuer, Audiences: []string{"test-app"}, TTL: time.Minute})
	require.NoError(t, err)
	delegated, err := embedded.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{Issuer: issuer, Audiences: []string{"test-app"}, DelegatedSubject: "some-user", Permissions: []string{"repo:models:deploy"}, TTL: time.Minute})
	require.NoError(t, err)
	target := func(*http.Request) verify.PermissionScope {
		return verify.PermissionScope{GroupID: beta, AuthorityIssuer: core.Config().Token.Issuer, Persona: "repo", Instance: "audit-beta"}
	}
	handler := verify.Required(srv.Verifier())(verify.RequirePermission(core, "repo:models:deploy", target)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	require.Equal(t, http.StatusForbidden, bearerStatus(t, handler, self), "self token is correctly restricted to alpha")
	got := bearerStatus(t, handler, delegated)
	t.Logf("alpha remote app requesting beta: self HTTP=403 delegated HTTP=%d", got)
	require.Equal(t, http.StatusForbidden, got, "delegation must not broaden alpha authority to beta")
}

// Audit regression: the HTTP verifier must follow the same live KeySource as
// minting and JWKS, including removing a compromised key.
func TestV1AuditLocalHTTPVerifierFollowsKeyRotation(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	keys := newSwappableKeySource(t, "audit-local-key-1")
	cfg := newServerTestConfig()
	cfg.Keys = embedded.KeysConfig{Source: keys}
	core := newServerClient(t, cfg, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	user, err := core.CreateUser(ctx, "audit-rotate@example.test", "audit-rotate")
	require.NoError(t, err)
	old, _, err := core.MintAccessToken(ctx, user.ID, nil)
	require.NoError(t, err)
	_, err = srv.Verifier().Verify(ctx, old)
	require.NoError(t, err)
	keys.rotate(t, "audit-local-key-2")
	fresh, _, err := core.MintAccessToken(ctx, user.ID, nil)
	require.NoError(t, err)
	_, err = srv.Verifier().Verify(ctx, fresh)
	if err != nil {
		t.Errorf("newly minted token rejected after live rotation: %v", err)
	}
	keys.mu.Lock()
	delete(keys.pubs, "audit-local-key-1")
	keys.mu.Unlock()
	require.NotContains(t, core.PublicKeysByKID(), "audit-local-key-1", "engine/JWKS source removed old key")
	_, err = srv.Verifier().Verify(ctx, old)
	if err == nil {
		t.Error("HTTP verifier still accepts removed local signing key")
	}
}

func TestV1AuditStaticRemoteKeyRotationReachesVerifier(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	core := newScopeBindingCore(t, pg.Pool)
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	gid := createRepoGroup(t, ctx, core, pg.Pool, "audit-remote-rotate")
	first, err := jwtkit.NewRSASigner(2048, "audit-remote-key-1")
	require.NoError(t, err)
	second, err := jwtkit.NewRSASigner(2048, "audit-remote-key-2")
	require.NoError(t, err)
	issuer := "https://audit-remote-rotate.example"
	app, err := core.UpsertRemoteApplication(ctx, authkit.RemoteApplication{Slug: "audit-remote-rotate", PermissionGroupID: gid, Issuer: issuer, Enabled: true, PublicKeys: []authkit.RemoteAppKey{{KID: first.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, first.PublicKey())}}})
	require.NoError(t, err)
	mint := func(s jwtkit.Signer) string {
		tok, err := embedded.MintRemoteApplicationAccessToken(ctx, s, authkit.RemoteApplicationAccessParams{Issuer: issuer, Audiences: []string{"test-app"}, TTL: time.Minute})
		require.NoError(t, err)
		return tok
	}
	old := mint(first)
	_, err = srv.Verifier().Verify(ctx, old)
	require.NoError(t, err)
	app.PublicKeys = []authkit.RemoteAppKey{{KID: second.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, second.PublicKey())}}
	_, err = core.UpsertRemoteApplication(ctx, *app)
	require.NoError(t, err)
	_, err = srv.Verifier().Verify(ctx, mint(second))
	if err != nil {
		t.Errorf("updated static remote key rejected: %v", err)
	}
	_, err = srv.Verifier().Verify(ctx, old)
	if err == nil {
		t.Error("removed static remote key remains accepted")
	}
}
