package authhttp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
)

// TestLazyLoadedIssuerEnforcesExpectedAudience pins ak#324 item 1: on the
// NewServer path (no LoadRemoteApplications call) a lazily-loaded remote
// application is registered with Config.Token.ExpectedAudiences, so a token it
// minted for a different audience is rejected.
func TestLazyLoadedIssuerEnforcesExpectedAudience(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	client := newServerClient(t, newServerTestConfig(), pool) // dev: loopback JWKS allowed
	srv, err := NewServer(client)
	require.NoError(t, err)
	core := embedded.Unwrap(client)
	gid, err := core.EnsureRootGroup(ctx)
	require.NoError(t, err)

	signer, err := jwtkit.NewRSASigner(2048, "aud-kid")
	require.NoError(t, err)
	jwks := newLoopbackJWKSServer(t, signer)
	ra, err := core.UpsertRemoteApplication(ctx, authcore.RemoteApplication{
		Slug: fmt.Sprintf("aud-%d", time.Now().UnixNano()), PermissionGroupID: gid,
		Issuer: jwks.URL, JWKSURI: jwks.URL + "/.well-known/jwks.json", Enabled: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
	})
	mint := func(aud string) string {
		tok, err := authcore.MintDelegatedAccessToken(ctx, signer, authkit.DelegatedAccessParams{
			Issuer: jwks.URL, Audiences: []string{aud}, DelegatedSubject: "u1", TTL: time.Minute,
		})
		require.NoError(t, err)
		return tok
	}

	_, err = srv.Verifier().Verify(mint("other-app"))
	require.Error(t, err, "wrong audience must be rejected by a lazily-loaded issuer")
	_, err = srv.Verifier().Verify(mint("test-app"))
	require.NoError(t, err)
}
