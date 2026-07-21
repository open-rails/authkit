package authhttp

// #257: dev servers register + fetch + verify against a loopback http JWKS
// endpoint; non-dev servers keep the SSRF-guarded fetch client and the
// registration-time rejections.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newLoopbackJWKSServer(t *testing.T, signer *jwtkit.RSASigner) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk := jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	srv := httptest.NewServer(mux) // binds http://127.0.0.1:<port>
	t.Cleanup(srv.Close)
	return srv
}

func TestDevServer_LoopbackJWKSFederation(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()

	signer, err := jwtkit.NewRSASigner(2048, "fed-kid")
	require.NoError(t, err)
	srv := newLoopbackJWKSServer(t, signer)

	cfg := newServerTestConfig() // Environment empty => dev
	client := newServerClient(t, cfg, pool)
	s, err := NewServer(client)
	require.NoError(t, err)

	core := embedded.Unwrap(client)
	gid, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	iss := srv.URL
	slug := fmt.Sprintf("dev-fed-%d", time.Now().UnixNano())
	ra, err := core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug:              slug,
		PermissionGroupID: gid,
		Issuer:            iss,
		JWKSURI:           srv.URL + "/.well-known/jwks.json",
		Enabled:           true,
	})
	require.NoError(t, err, "dev registration must accept a loopback http jwks_uri")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
	})

	aud := []string{"test-app"}
	require.NoError(t, s.Verifier().LoadRemoteApplications(ctx, nil, aud))

	tok, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1", TTL: time.Minute,
	})
	require.NoError(t, err)
	_, err = s.Verifier().Verify(tok)
	require.NoError(t, err, "dev verifier must fetch JWKS from 127.0.0.1 and verify")
}

func TestProdServer_LoopbackJWKSStillRejected(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()

	signer, err := jwtkit.NewRSASigner(2048, "fed-kid-prod")
	require.NoError(t, err)
	srv := newLoopbackJWKSServer(t, signer)

	cfg := newServerTestConfig()
	cfg.Environment = "production"
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"}) // lazy; never contacted
	t.Cleanup(func() { _ = rdb.Close() })
	client := newServerClient(t, cfg, pool)
	s, err := NewServer(client, WithRedis(rdb))
	require.NoError(t, err)

	core := embedded.Unwrap(client)
	gid, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	// Registration stays fail-closed with today's messages.
	slug := fmt.Sprintf("prod-fed-%d", time.Now().UnixNano())
	_, err = core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug: slug, PermissionGroupID: gid,
		Issuer: srv.URL, JWKSURI: srv.URL + "/.well-known/jwks.json", Enabled: true,
	})
	require.ErrorContains(t, err, "jwks_uri must use https")
	_, err = core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug: slug, PermissionGroupID: gid,
		Issuer: "https://127.0.0.1:1/x", JWKSURI: "https://127.0.0.1:1/jwks", Enabled: true,
	})
	require.ErrorContains(t, err, "private/reserved IP — not allowed")

	// Fetch-time: even a directly-added loopback issuer is refused by the
	// SSRF-guarded dialer, so verification cannot succeed.
	aud := []string{"test-app"}
	require.NoError(t, s.Verifier().AddIssuer(srv.URL, aud, verify.IssuerOptions{
		JWKSURI: srv.URL + "/.well-known/jwks.json",
	}))
	tok, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
		Issuer: srv.URL, Audiences: aud, DelegatedSubject: "u1", TTL: time.Minute,
	})
	require.NoError(t, err)
	_, err = s.Verifier().Verify(tok)
	require.Error(t, err, "prod verifier must not fetch JWKS from 127.0.0.1")
}
