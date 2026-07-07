package authhttp

// #248: machine-principal permission checks must be instance-AWARE. An API key
// or remote-application token is minted ON a permission-group instance; its
// token-carried permissions are valid only on that exact instance.

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

// newScopeBindingCore builds a DB-backed core service with a multi-instance
// `repo` persona under root, so keys can be minted on distinct instances.
func newScopeBindingCore(t *testing.T, pool *pgxpool.Pool) *authcore.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "scope-bind-kid")
	require.NoError(t, err)
	coreSvc, err := authcore.NewFromConfig(authcore.Config{
		Token: authcore.TokenConfig{
			Issuer:              "https://scope-bind.example",
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		Registration: authcore.RegistrationConfig{Verification: authcore.RegistrationVerificationNone},
		Keys: authcore.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		}},
		RBAC: []authcore.PersonaDef{
			authcore.IntrinsicRootPersona(),
			{Name: "repo", Parent: authcore.RootPersona, Roles: []authcore.RoleDef{
				{Name: "deployer", Permissions: []string{"repo:models:deploy"}},
			}},
		},
	}, pool)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, coreSvc.SeedPermissionGroupContainment(ctx))
	_, err = coreSvc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	return coreSvc
}

func createRepoGroup(t *testing.T, ctx context.Context, coreSvc *authcore.Service, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	gid, err := coreSvc.CreatePermissionGroup(ctx, authcore.CreatePermissionGroupRequest{Persona: "repo", InstanceSlug: slug})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.permission_groups WHERE id = $1::uuid`, gid)
	})
	return gid
}

func bearerStatus(t *testing.T, h http.Handler, token string) int {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, r)
	return w.Code
}

// An API key minted on repo instance "alpha" passes the verify.RequirePermission
// gate only on scope {repo, alpha}: cross-instance and unresolvable scopes deny.
func TestAPIKeyGroupBinding_EndToEnd(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	coreSvc := newScopeBindingCore(t, pool)

	suffix := time.Now().UnixNano()
	alpha := fmt.Sprintf("alpha%d", suffix)
	beta := fmt.Sprintf("beta%d", suffix)
	createRepoGroup(t, ctx, coreSvc, pool, alpha)
	createRepoGroup(t, ctx, coreSvc, pool, beta)

	// Minting requires a creator whose authority covers the key's role: seed an
	// owner of the alpha group.
	username := fmt.Sprintf("scopebind%d", suffix)
	u, err := coreSvc.CreateUser(ctx, username+"@test.example", username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.users WHERE id = $1::uuid`, u.ID)
	})
	require.NoError(t, coreSvc.AssignGroupRole(ctx, "repo", alpha, u.ID, authcore.SubjectKindUser, authcore.OwnerRoleName))

	_, token, err := coreSvc.MintAPIKey(ctx, "repo", alpha, "ci-key", "deployer", u.ID, nil)
	require.NoError(t, err)

	// The resolved key carries its owning group instance.
	keyID, secret, ok := authkit.ParseAPIKey("", token)
	require.True(t, ok)
	resolved, err := coreSvc.ResolveAPIKeyDetailed(ctx, keyID, secret)
	require.NoError(t, err)
	require.Equal(t, "repo", resolved.Persona)
	require.Equal(t, alpha, resolved.InstanceSlug)
	require.Contains(t, resolved.Permissions, "repo:models:deploy")

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second)).WithService(coreSvc)
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gate := func(resolve func(*http.Request) verify.PermissionScope) http.Handler {
		return verify.Required(ver)(verify.RequirePermission(coreSvc, "repo:models:deploy", resolve)(okHandler))
	}
	scopeOf := func(inst string) func(*http.Request) verify.PermissionScope {
		return func(*http.Request) verify.PermissionScope {
			return verify.PermissionScope{Persona: "repo", Instance: inst}
		}
	}

	require.Equal(t, http.StatusOK, bearerStatus(t, gate(scopeOf(alpha)), token), "owning instance must allow")
	require.Equal(t, http.StatusForbidden, bearerStatus(t, gate(scopeOf(beta)), token), "cross-instance must deny")
	require.Equal(t, http.StatusForbidden, bearerStatus(t, gate(nil), token), "bound principal with no resolvable scope must deny")
}

// A remote-application access token is bound to the group instance its
// remote_application row is nested under, resolved server-side at verify.
func TestRemoteAppTokenGroupBinding_EndToEnd(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	coreSvc := newScopeBindingCore(t, pool)

	suffix := time.Now().UnixNano()
	alpha := fmt.Sprintf("ra-alpha%d", suffix)
	gid := createRepoGroup(t, ctx, coreSvc, pool, alpha)

	signer, err := jwtkit.NewRSASigner(2048, "scope-bind-ra-kid")
	require.NoError(t, err)
	issuer := fmt.Sprintf("https://scope-bind-%d.example", suffix)
	ra, err := coreSvc.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              fmt.Sprintf("scope-bind-%d", suffix),
		PermissionGroupID: gid,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []authkit.RemoteAppKey{{
			KID:          signer.KID(),
			PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey()),
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = coreSvc.DeleteRemoteApplication(context.Background(), issuer)
	})
	require.NoError(t, coreSvc.AddRemoteApplicationMember(ctx, ra.ID, "deployer"))

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second)).WithService(coreSvc)
	require.NoError(t, ver.AddIssuer(issuer, []string{"test-app"}, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{
		Issuer:    issuer,
		Audiences: []string{"test-app"},
		TTL:       time.Minute,
	})
	require.NoError(t, err)

	cl, err := ver.Verify(token)
	require.NoError(t, err)
	require.Equal(t, "repo", cl.PermissionGroupPersona)
	require.Equal(t, alpha, cl.PermissionGroupInstance)
	require.Contains(t, cl.Permissions, "repo:models:deploy")

	allowed, err := verify.Allow(ctx, coreSvc, cl, "repo:models:deploy", verify.PermissionScope{Persona: "repo", Instance: alpha})
	require.NoError(t, err)
	require.True(t, allowed, "owning instance must allow")
	allowed, err = verify.Allow(ctx, coreSvc, cl, "repo:models:deploy", verify.PermissionScope{Persona: "repo", Instance: "other"})
	require.NoError(t, err)
	require.False(t, allowed, "cross-instance must deny")
}

// The delegated-token contract is UNCHANGED by #248: delegated authorization is
// issuer-trust + permissions (the receiving service's model). Even though the
// issuing remote_application is nested under a group instance — and the same
// server-side authority resolver now returns that (persona, instance) — a
// verified delegated token must stay UNBOUND and its token-carried permissions
// must remain valid on ANY scope.
func TestDelegatedTokenContractUnchanged_EndToEnd(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	coreSvc := newScopeBindingCore(t, pool)

	suffix := time.Now().UnixNano()
	alpha := fmt.Sprintf("dl-alpha%d", suffix)
	gid := createRepoGroup(t, ctx, coreSvc, pool, alpha)

	signer, err := jwtkit.NewRSASigner(2048, "scope-bind-dl-kid")
	require.NoError(t, err)
	issuer := fmt.Sprintf("https://scope-bind-dl-%d.example", suffix)
	ra, err := coreSvc.UpsertRemoteApplication(ctx, authkit.RemoteApplication{
		Slug:              fmt.Sprintf("scope-bind-dl-%d", suffix),
		PermissionGroupID: gid,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys: []authkit.RemoteAppKey{{
			KID:          signer.KID(),
			PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey()),
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = coreSvc.DeleteRemoteApplication(context.Background(), issuer)
	})
	require.NoError(t, coreSvc.AddRemoteApplicationMember(ctx, ra.ID, "deployer"))

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second)).WithService(coreSvc)
	require.NoError(t, ver.AddIssuer(issuer, []string{"test-app"}, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
		Issuer:           issuer,
		Audiences:        []string{"test-app"},
		DelegatedSubject: "delegated-user-1",
		Permissions:      []string{"repo:models:deploy"}, // within the app's stored ceiling
		TTL:              time.Minute,
	})
	require.NoError(t, err)

	cl, err := ver.Verify(token)
	require.NoError(t, err)
	require.False(t, cl.BoundToPermissionGroup(), "delegated tokens must stay unbound")
	require.Empty(t, cl.PermissionGroupPersona)
	require.Empty(t, cl.PermissionGroupInstance)
	require.Contains(t, cl.Permissions, "repo:models:deploy")

	// Cross-instance and unresolvable scopes both remain ALLOWED for delegated
	// tokens — exactly where a bound machine principal is denied.
	allowed, err := verify.Allow(ctx, coreSvc, cl, "repo:models:deploy", verify.PermissionScope{Persona: "repo", Instance: "any-other"})
	require.NoError(t, err)
	require.True(t, allowed, "delegated token-carried perm must remain scope-free")

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gate := verify.Required(ver)(verify.RequirePermission(coreSvc, "repo:models:deploy", nil)(okHandler))
	require.Equal(t, http.StatusOK, bearerStatus(t, gate, token), "delegated token must pass without a resolvable scope")
}

// authhttp's intrinsic requirePermission applies the same binding: a root-bound
// key passes the root gate; a repo-bound key is denied there even if it somehow
// carried a matching permission string.
func TestIntrinsicRequirePermission_GroupBoundMachinePrincipal(t *testing.T) {
	s := &Service{} // machine branch never touches s.svc
	h := s.requirePermission(embedded.RootPersona, "", "root:users:list",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	rootBound := &verify.Claims{
		TokenType:              verify.APIKeyPrincipalType,
		Permissions:            []string{"root:users:list"},
		PermissionGroupPersona: embedded.RootPersona,
	}
	require.Equal(t, http.StatusOK, serveWithClaims(h, rootBound).Code)

	repoBound := &verify.Claims{
		TokenType:               verify.APIKeyPrincipalType,
		Permissions:             []string{"root:users:list"},
		PermissionGroupPersona:  "repo",
		PermissionGroupInstance: "alpha",
	}
	require.Equal(t, http.StatusForbidden, serveWithClaims(h, repoBound).Code)
}
