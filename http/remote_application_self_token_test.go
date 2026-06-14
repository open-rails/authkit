package authhttp

import (
	"context"
	"crypto"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// selfTokenEnv wires a DB-backed verifier for the JWKS-principal SELF-token path
// (#76): a registered remote_application, the verifier trusting its external
// signing key, and the core.Service that resolves its STORED authority.
type selfTokenEnv struct {
	pool   *pgxpool.Pool
	svc    *core.Service
	ver    *Verifier
	signer *jwtkit.RSASigner
	app    *core.RemoteApplication
	iss    string
	aud    []string
}

func newSelfTokenEnv(t *testing.T, slug, iss string) *selfTokenEnv {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	svc := core.NewService(core.Options{Issuer: "https://authkit.test"}, core.Keyset{}).WithPostgres(pool)

	// External principal's own signing key + a JWKS endpoint for it.
	signer, err := jwtkit.NewRSASigner(2048, "remote-app-kid")
	require.NoError(t, err)

	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })

	jwks := jwksServer(t, signer)
	t.Cleanup(jwks.Close)
	app, err := svc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug: slug, Issuer: iss, JWKSURI: jwks.URL + "/.well-known/jwks.json", Enabled: true,
	})
	require.NoError(t, err)

	aud := []string{"openrails"}
	ver := NewVerifier().WithService(svc)
	// Trust the principal's external key directly (equivalent to LoadRemoteApplications
	// fetching its JWKS; here we seed the key so the test needs no live fetch).
	require.NoError(t, ver.AddIssuer(iss, aud, IssuerOptions{
		RawKeys:    map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		TenantSlug: slug,
	}))
	return &selfTokenEnv{pool: pool, svc: svc, ver: ver, signer: signer, app: app, iss: iss, aud: aud}
}

func (e *selfTokenEnv) mint(t *testing.T) string {
	t.Helper()
	tok, err := core.MintRemoteApplicationAccessToken(context.Background(), e.signer, core.RemoteApplicationAccessParams{
		Issuer: e.iss, Audiences: e.aud, TTL: time.Minute,
	})
	require.NoError(t, err)
	return tok
}

// TestRemoteApplicationSelfTokenResolvesStoredAuthority is the core #76 case: a
// JWKS principal self-token authenticates AS the remote_application and resolves
// its ASSIGNED authority — direct permissions UNION role-derived permissions —
// and exposes its tenant role. Self-claimed authority on the token is ignored.
func TestRemoteApplicationSelfTokenResolvesStoredAuthority(t *testing.T) {
	env := newSelfTokenEnv(t, "self-app", "https://self-app.example/iss")
	ctx := context.Background()

	const tslug = "self-tenant"
	_, _ = env.pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, tslug)
	t.Cleanup(func() { _, _ = env.pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, tslug) })
	_, err := env.svc.CreateTenant(ctx, tslug)
	require.NoError(t, err)

	// A role that bundles a permission, assigned to the principal.
	require.NoError(t, env.svc.DefineRole(ctx, tslug, "catalog-admin"))
	require.NoError(t, env.svc.SetRolePermissions(ctx, tslug, "catalog-admin", []string{"catalog:write"}))
	require.NoError(t, env.svc.AddRemoteApplicationMember(ctx, tslug, env.app.ID, "catalog-admin"))
	// A DIRECT permission grant.
	require.NoError(t, env.svc.AddRemoteApplicationPermission(ctx, env.app.ID, "billing:read"))

	cl, err := env.ver.Verify(env.mint(t))
	require.NoError(t, err)

	require.True(t, cl.IsRemoteApplication())
	require.False(t, cl.IsService())
	require.False(t, cl.IsDelegated())
	require.Empty(t, cl.UserID, "self-token implies no local user")
	require.Equal(t, env.app.ID, cl.RemoteApplicationID)
	require.Equal(t, "self-app", cl.RemoteApplicationSlug)
	require.Equal(t, tslug, cl.Tenant)
	require.Contains(t, cl.TenantRoles, "catalog-admin")
	// Effective permissions = role-derived ∪ direct.
	require.ElementsMatch(t, []string{"catalog:write", "billing:read"}, cl.Permissions)
}

// TestRemoteApplicationSelfTokenIgnoresSelfClaimedAuthority proves a hostile
// self-signed token cannot grant itself permissions/roles: authority is STORED
// only. We sign a token with bogus permissions/roles claims and assert the
// verified Claims carry ONLY what was assigned (here: nothing).
func TestRemoteApplicationSelfTokenIgnoresSelfClaimedAuthority(t *testing.T) {
	env := newSelfTokenEnv(t, "noescal-app", "https://noescal-app.example/iss")
	now := time.Now()
	tok, err := env.signer.SignWithHeaders(context.Background(), map[string]any{
		"iss":         env.iss,
		"aud":         env.aud,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"permissions": []string{"admin:everything", "billing:write"},
		"roles":       []string{"owner"},
		"tenant":      "some-other-tenant",
	}, map[string]any{"typ": RemoteApplicationAccessTokenType})
	require.NoError(t, err)

	cl, err := env.ver.Verify(tok)
	require.NoError(t, err)
	require.True(t, cl.IsRemoteApplication())
	require.Empty(t, cl.Permissions, "self-claimed permissions must NOT be honored")
	require.Empty(t, cl.Roles, "self-claimed roles must NOT be honored")
	require.Empty(t, cl.Tenant, "self-claimed tenant must NOT be honored")
}

// TestRemoteApplicationSelfTokenGrantTakesEffect proves assigning then removing a
// direct permission is reflected on the next verify.
func TestRemoteApplicationSelfTokenGrantTakesEffect(t *testing.T) {
	env := newSelfTokenEnv(t, "grant-app", "https://grant-app.example/iss")
	ctx := context.Background()

	cl, err := env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Empty(t, cl.Permissions)

	require.NoError(t, env.svc.AddRemoteApplicationPermission(ctx, env.app.ID, "jobs:submit"))
	cl, err = env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Equal(t, []string{"jobs:submit"}, cl.Permissions)

	removed, err := env.svc.RemoveRemoteApplicationPermission(ctx, env.app.ID, "jobs:submit")
	require.NoError(t, err)
	require.True(t, removed)
	cl, err = env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Empty(t, cl.Permissions)
}

// TestRemoteApplicationSelfTokenRejectsSubject regression-guards the verifier's
// subject invariant (verifier.go:666 family): a self-token must carry neither
// `sub` nor `delegated_sub`.
func TestRemoteApplicationSelfTokenRejectsSubject(t *testing.T) {
	env := newSelfTokenEnv(t, "subj-app", "https://subj-app.example/iss")
	now := time.Now()
	for _, subjectClaim := range []string{"sub", "delegated_sub"} {
		tok, err := env.signer.SignWithHeaders(context.Background(), map[string]any{
			"iss":        env.iss,
			"aud":        env.aud,
			"iat":        now.Unix(),
			"exp":        now.Add(time.Minute).Unix(),
			subjectClaim: "smuggled",
		}, map[string]any{"typ": RemoteApplicationAccessTokenType})
		require.NoError(t, err)
		_, err = env.ver.Verify(tok)
		require.Error(t, err, "self-token with %s must be rejected", subjectClaim)
	}
}
