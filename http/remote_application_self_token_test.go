package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// selfTokenEnv wires a DB-backed verifier for the remote application access
// token path (#76): a registered remote_application, the verifier trusting its
// external signing key, and the core.Service that resolves its STORED authority.
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

	svc := core.NewService(core.Options{Issuer: "https://authkit.test"}, core.Keyset{}, core.WithPostgres(pool))

	// External principal's own signing key + a JWKS endpoint for it.
	signer, err := jwtkit.NewRSASigner(2048, "remote-app-kid")
	require.NoError(t, err)

	// #77: each issuer belongs to exactly one org (org_id NOT NULL). Register the
	// org cleanup first so the RA cleanup (LIFO) runs before it (FK order).
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug) })
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })
	org, err := svc.CreateOrg(ctx, slug)
	require.NoError(t, err)

	// The verifier trusts this principal's signing key directly via RawKeys below,
	// so its JWKS endpoint is never fetched. Store an https jwks_uri to satisfy the
	// SSRF guard (jwks_uri must be https) without standing up a live server.
	app, err := svc.UpsertRemoteApplication(ctx, core.RemoteApplication{
		Slug: slug, OrgID: org.ID, Issuer: iss, JWKSURI: "https://" + slug + ".jwks.test/.well-known/jwks.json", Enabled: true,
	})
	require.NoError(t, err)

	aud := []string{"openrails"}
	ver := NewVerifier().WithService(svc)
	// Trust the principal's external key directly (equivalent to LoadRemoteApplications
	// fetching its JWKS; here we seed the key so the test needs no live fetch).
	require.NoError(t, ver.AddIssuer(iss, aud, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		OrgSlug: slug,
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

// mintScoped mints a remote application access token carrying a `permissions`
// down-scoping claim (#76 amendment). A nil perms slice means "no claim" (full
// ceiling).
func (e *selfTokenEnv) mintScoped(t *testing.T, perms []string) string {
	t.Helper()
	tok, err := core.MintRemoteApplicationAccessToken(context.Background(), e.signer, core.RemoteApplicationAccessParams{
		Issuer: e.iss, Audiences: e.aud, TTL: time.Minute, Permissions: perms,
	})
	require.NoError(t, err)
	return tok
}

// TestRemoteApplicationSelfTokenResolvesStoredAuthority is the core #76 case: a
// remote application access token authenticates AS the remote_application and
// resolves its ASSIGNED role-derived authority. Role claims in the token are
// ignored.
func TestRemoteApplicationSelfTokenResolvesStoredAuthority(t *testing.T) {
	env := newSelfTokenEnv(t, "self-app", "https://self-app.example/iss")
	ctx := context.Background()

	const tslug = "self-org"
	_, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	t.Cleanup(func() { _, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug) })
	_, err := env.svc.CreateOrg(ctx, tslug)
	require.NoError(t, err)

	// A role that bundles permissions, assigned to the principal.
	require.NoError(t, env.svc.DefineRole(ctx, tslug, "catalog-admin"))
	require.NoError(t, env.svc.SetRolePermissions(ctx, tslug, "catalog-admin", []string{"catalog:write", "billing:read"}))
	require.NoError(t, env.svc.AddRemoteApplicationMember(ctx, tslug, env.app.ID, "catalog-admin"))

	cl, err := env.ver.Verify(env.mint(t))
	require.NoError(t, err)

	require.True(t, cl.IsRemoteApplication())
	require.False(t, cl.IsService())
	require.False(t, cl.IsDelegated())
	require.Empty(t, cl.UserID, "remote application access token implies no local user")
	require.Equal(t, env.app.ID, cl.RemoteApplicationID)
	require.Equal(t, "self-app", cl.RemoteApplicationSlug)
	require.Equal(t, tslug, cl.Org)
	require.Contains(t, cl.OrgRoles, "catalog-admin")
	// Effective permissions are role-derived.
	require.ElementsMatch(t, []string{"catalog:write", "billing:read"}, cl.Permissions)
}

// TestRemoteApplicationSelfTokenIgnoresSelfClaimedAuthority proves a hostile
// self-signed token cannot grant itself authority: roles/org claims are STORED
// only and never honored, and a `permissions` over-claim (now a down-scoping
// request, #76 amendment) REJECTS rather than escalating. With no perms claim the
// verified Claims carry ONLY what was assigned (here: nothing).
func TestRemoteApplicationSelfTokenIgnoresSelfClaimedAuthority(t *testing.T) {
	env := newSelfTokenEnv(t, "noescal-app", "https://noescal-app.example/iss")
	now := time.Now()

	// Bogus roles/org (and NO permissions claim) are ignored, not honored.
	tok, err := env.signer.SignWithHeaders(context.Background(), map[string]any{
		"iss":   env.iss,
		"aud":   env.aud,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Minute).Unix(),
		"roles": []string{"owner"},
		"org":   "some-other-org",
	}, map[string]any{"typ": RemoteApplicationAccessTokenType})
	require.NoError(t, err)
	cl, err := env.ver.Verify(tok)
	require.NoError(t, err)
	require.True(t, cl.IsRemoteApplication())
	require.Empty(t, cl.Permissions, "self-claimed permissions must NOT be honored")
	require.Empty(t, cl.Roles, "self-claimed roles must NOT be honored")
	require.Empty(t, cl.Org, "self-claimed org must NOT be honored")

	// A `permissions` over-claim can no longer escalate — it rejects the token.
	tok2, err := env.signer.SignWithHeaders(context.Background(), map[string]any{
		"iss":         env.iss,
		"aud":         env.aud,
		"iat":         now.Unix(),
		"exp":         now.Add(time.Minute).Unix(),
		"permissions": []string{"admin:everything", "billing:write"},
	}, map[string]any{"typ": RemoteApplicationAccessTokenType})
	require.NoError(t, err)
	_, err = env.ver.Verify(tok2)
	require.Error(t, err, "self-claimed permissions must reject, not escalate")
	require.Contains(t, err.Error(), "permission_not_granted")
}

// TestRemoteApplicationSelfTokenRoleGrantTakesEffect proves assigning then
// removing an org role is reflected on the next verify.
func TestRemoteApplicationSelfTokenRoleGrantTakesEffect(t *testing.T) {
	env := newSelfTokenEnv(t, "grant-app", "https://grant-app.example/iss")
	ctx := context.Background()
	const tslug = "grant-org"
	_, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	t.Cleanup(func() { _, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug) })
	_, err := env.svc.CreateOrg(ctx, tslug)
	require.NoError(t, err)
	require.NoError(t, env.svc.DefineRole(ctx, tslug, "runner"))
	require.NoError(t, env.svc.SetRolePermissions(ctx, tslug, "runner", []string{"jobs:submit"}))

	cl, err := env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Empty(t, cl.Permissions)

	require.NoError(t, env.svc.AddRemoteApplicationMember(ctx, tslug, env.app.ID, "runner"))
	cl, err = env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Equal(t, []string{"jobs:submit"}, cl.Permissions)

	require.NoError(t, env.svc.RemoveRemoteApplicationMember(ctx, tslug, env.app.ID))
	cl, err = env.ver.Verify(env.mint(t))
	require.NoError(t, err)
	require.Empty(t, cl.Permissions)
}

// seedCeiling assigns a remote_application a role whose permissions create a
// ceiling of catalog:write + billing:read.
func seedCeiling(t *testing.T, env *selfTokenEnv, tslug string) {
	t.Helper()
	ctx := context.Background()
	_, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug)
	t.Cleanup(func() { _, _ = env.pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, tslug) })
	_, err := env.svc.CreateOrg(ctx, tslug)
	require.NoError(t, err)
	require.NoError(t, env.svc.DefineRole(ctx, tslug, "catalog-admin"))
	require.NoError(t, env.svc.SetRolePermissions(ctx, tslug, "catalog-admin", []string{"catalog:write", "billing:read"}))
	require.NoError(t, env.svc.AddRemoteApplicationMember(ctx, tslug, env.app.ID, "catalog-admin"))
}

// TestRemoteApplicationSelfTokenDownScopesToSubset (#76 amendment): a `permissions`
// claim narrows the stored ceiling to the intersection. Roles still contribute to
// the ceiling, so a role-derived perm can be selected by the claim.
func TestRemoteApplicationSelfTokenDownScopesToSubset(t *testing.T) {
	env := newSelfTokenEnv(t, "scope-app", "https://scope-app.example/iss")
	seedCeiling(t, env, "scope-org")

	// Claim only the role-derived perm => effective = {catalog:write}.
	cl, err := env.ver.Verify(env.mintScoped(t, []string{"catalog:write"}))
	require.NoError(t, err)
	require.True(t, cl.IsRemoteApplication())
	require.Equal(t, []string{"catalog:write"}, cl.Permissions)
}

// TestRemoteApplicationSelfTokenCannotWiden (#76 amendment, REVISED): a claim for
// a perm OUTSIDE the stored ceiling REJECTS the whole token with
// permission_not_granted — not a silent clamp — so a misconfigured caller fails
// loudly. The in-grant perm in the same claim does NOT rescue it.
func TestRemoteApplicationSelfTokenCannotWiden(t *testing.T) {
	env := newSelfTokenEnv(t, "widen-app", "https://widen-app.example/iss")
	seedCeiling(t, env, "widen-org")

	_, err := env.ver.Verify(env.mintScoped(t, []string{"billing:read", "admin:everything"}))
	require.Error(t, err, "out-of-grant claimed perm must reject the token")
	require.Contains(t, err.Error(), "permission_not_granted")
}

// TestRemoteApplicationSelfTokenAbsentClaimFullCeiling (#76 amendment)
// regression-guards the v0.28.0 behavior: a remote application access token with
// NO `permissions` claim resolves the FULL stored role-derived ceiling —
// backward-compatible.
func TestRemoteApplicationSelfTokenAbsentClaimFullCeiling(t *testing.T) {
	env := newSelfTokenEnv(t, "absent-app", "https://absent-app.example/iss")
	seedCeiling(t, env, "absent-org")

	cl, err := env.ver.Verify(env.mint(t)) // mint() carries no permissions claim
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"catalog:write", "billing:read"}, cl.Permissions)
}

// callMePermissions invokes the introspection handler directly with the given
// claims in context and returns the decoded JSON body. Driving the handler with
// pre-resolved claims isolates the endpoint's resolution logic from the auth
// middleware (covered elsewhere).
func callMePermissions(t *testing.T, pool *pgxpool.Pool, cl Claims) map[string]any {
	t.Helper()
	s, err := NewServer(core.Config{
		Token: core.TokenConfig{
			Issuer:            "https://authkit.test",
			IssuedAudiences:   []string{"openrails"},
			ExpectedAudiences: []string{"openrails"},
		},
		Frontend: core.FrontendConfig{BaseURL: "https://authkit.test"},
	}, pool)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
	r = r.WithContext(setClaims(r.Context(), cl))
	w := httptest.NewRecorder()
	s.handleMePermissionsGET(w, r)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	return out
}

func toStrings(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	require.True(t, ok, "expected array, got %T", v)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		out = append(out, e.(string))
	}
	return out
}

// TestMePermissionsRemoteAppReturnsCeiling (#76 amendment): the introspection
// endpoint returns a remote application's full GRANTED ceiling resolved by
// identity — NOT the (narrowed) Permissions of the presented token — so a caller
// can discover its grant before minting a valid down-scoped token.
func TestMePermissionsRemoteAppReturnsCeiling(t *testing.T) {
	env := newSelfTokenEnv(t, "intro-app", "https://intro-app.example/iss")
	seedCeiling(t, env, "intro-org")

	// Present a NARROWED token (claims only one of two ceiling perms).
	cl, err := env.ver.Verify(env.mintScoped(t, []string{"billing:read"}))
	require.NoError(t, err)
	require.Equal(t, []string{"billing:read"}, cl.Permissions, "presented token is narrowed")

	out := callMePermissions(t, env.pool, cl)
	require.Equal(t, "remote_application", out["principal_type"])
	require.Equal(t, env.app.ID, out["id"])
	require.Equal(t, "intro-app", out["slug"])
	require.Equal(t, "intro-org", out["org"])
	require.Contains(t, toStrings(t, out["roles"]), "catalog-admin")
	// The FULL ceiling, not the narrowed claim.
	require.ElementsMatch(t, []string{"catalog:write", "billing:read"}, toStrings(t, out["permissions"]))
}

// TestMePermissionsServicePrincipalReturnsStored: a service principal's stored
// permissions ride on its claims and are echoed back.
func TestMePermissionsServicePrincipalReturnsStored(t *testing.T) {
	env := newSelfTokenEnv(t, "svc-intro-app", "https://svc-intro-app.example/iss")
	cl := Claims{
		TokenType:   ServicePrincipalType,
		Org:         "svc-org",
		OrgRoles:    []string{"runner"},
		Permissions: []string{"jobs:submit", "jobs:read"},
	}
	out := callMePermissions(t, env.pool, cl)
	require.Equal(t, "service", out["principal_type"])
	require.Equal(t, "svc-org", out["org"])
	require.ElementsMatch(t, []string{"jobs:submit", "jobs:read"}, toStrings(t, out["permissions"]))
}

// TestRemoteApplicationSelfTokenRejectsSubject regression-guards the verifier's
// subject invariant: a remote application access token must carry neither `sub`
// nor `delegated_sub`.
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
		require.Error(t, err, "remote application access token with %s must be rejected", subjectClaim)
	}
}
