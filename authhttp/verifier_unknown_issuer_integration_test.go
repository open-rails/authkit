package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
)

// TestVerifier_UnknownIssuerFlood_BoundedStoreLoad pins ak#297 on the real
// mount: N distinct garbage `iss` values on a gated route cost at most one
// enabled-issuer list query in total, never a per-issuer lookup, and leave no
// per-issuer verifier state.
func TestVerifier_UnknownIssuerFlood_BoundedStoreLoad(t *testing.T) {
	counter := newQueryCounter("RemoteApplicationsEnabled", "RemoteApplicationByIssuer")
	pool := newTracedServerTestPool(t, counter)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)
	signer, err := jwtkit.NewRSASigner(2048, "garbage-kid")
	require.NoError(t, err)
	h := srv.APIHandler()
	get := func(token string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.ServeHTTP(w, r)
		return w.Code
	}

	counter.arm()
	for i := 0; i < 300; i++ {
		require.Equal(t, http.StatusUnauthorized, get(mintAccessJWT(t, signer, fmt.Sprintf("https://garbage-%d.example", i), nil)))
	}
	require.LessOrEqual(t, counter.count("RemoteApplicationsEnabled"), 1, "one snapshot refresh for the whole flood")
	require.Equal(t, 0, counter.count("RemoteApplicationByIssuer"), "no per-issuer store read")

	lists := counter.count("RemoteApplicationsEnabled")
	for _, iss := range []string{"not-a-url", strings.Repeat("a", 600), "https://" + strings.Repeat("h", 600) + ".example", "https://x.example/with space"} {
		require.Equal(t, http.StatusUnauthorized, get(mintAccessJWT(t, signer, iss, nil)), iss)
	}
	require.Equal(t, lists, counter.count("RemoteApplicationsEnabled"), "shape-refused issuers never touch the store")

	stats := srv.Verifier().FederationStats()
	require.Zero(t, stats.Negative)
	require.Zero(t, stats.InFlight)
}

// TestVerifier_NewRemoteApplicationLazyLoadsOnFirstUse keeps the ak#42
// contract on the NewServer path (no LoadRemoteApplications call): a freshly
// registered application verifies on first use, one registered after a
// snapshot was taken becomes visible within one snapshot TTL, and registration
// refuses an issuer the verifier would never consult the store for.
func TestVerifier_NewRemoteApplicationLazyLoadsOnFirstUse(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	client := newServerClient(t, newServerTestConfig(), pool) // dev: loopback JWKS allowed
	srv, err := NewServer(client)
	require.NoError(t, err)
	core := embedded.Unwrap(client)
	gid, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	register := func(name string) (string, *jwtkit.RSASigner) {
		t.Helper()
		signer, err := jwtkit.NewRSASigner(2048, name+"-kid")
		require.NoError(t, err)
		jwks := newLoopbackJWKSServer(t, signer)
		ra, err := core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
			Slug: fmt.Sprintf("%s-%d", name, time.Now().UnixNano()), PermissionGroupID: gid,
			Issuer: jwks.URL, JWKSURI: jwks.URL + "/.well-known/jwks.json", Enabled: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
		})
		return jwks.URL, signer
	}
	mint := func(signer *jwtkit.RSASigner, iss string) string {
		t.Helper()
		tok, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
			Issuer: iss, Audiences: []string{"test-app"}, DelegatedSubject: "u1", TTL: time.Minute,
		})
		require.NoError(t, err)
		return tok
	}

	iss1, signer1 := register("lazy-first")
	_, err = srv.Verifier().Verify(context.Background(), mint(signer1, iss1))
	require.NoError(t, err, "first use registers the issuer from a fresh snapshot")

	iss2, signer2 := register("lazy-second")
	require.Eventually(t, func() bool {
		_, err := srv.Verifier().Verify(context.Background(), mint(signer2, iss2))
		return err == nil
	}, 10*time.Second, 200*time.Millisecond, "an application registered after the snapshot is visible within one TTL")

	_, err = core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug: fmt.Sprintf("bad-iss-%d", time.Now().UnixNano()), PermissionGroupID: gid,
		Issuer: "not-a-url", JWKSURI: iss1 + "/.well-known/jwks.json", Enabled: true,
	})
	require.ErrorIs(t, err, authkit.ErrInvalidRemoteApplication)
}
