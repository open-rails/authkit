package authhttp

import (
	"context"
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// #323: disabling a remote application must reject its tokens on the very
// next verification, not at the next LoadRemoteApplications reconcile. Real
// engine + Postgres; the issuer stays registered with valid keys throughout.
func TestDisabledRemoteApplicationTokenRejectedImmediately(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	coreSvc := newScopeBindingCore(t, pool)

	suffix := time.Now().UnixNano()
	gid := createRepoGroup(t, ctx, coreSvc, pool, fmt.Sprintf("ra-disabled%d", suffix))
	signer, err := jwtkit.NewRSASigner(2048, "disabled-ra-kid")
	require.NoError(t, err)
	issuer := fmt.Sprintf("https://disabled-%d.example", suffix)
	app := authkit.RemoteApplication{
		Slug:              fmt.Sprintf("disabled-%d", suffix),
		PermissionGroupID: gid,
		Issuer:            issuer,
		Enabled:           true,
		PublicKeys:        []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: adminTestPublicKeyPEM(t, signer.PublicKey())}},
	}
	ra, err := coreSvc.UpsertRemoteApplication(ctx, app)
	require.NoError(t, err)
	t.Cleanup(func() { _ = coreSvc.DeleteRemoteApplication(context.Background(), issuer) })
	require.NoError(t, coreSvc.AssignRemoteApplicationRole(ctx, ra.ID, "deployer"))

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second)).WithService(coreSvc)
	require.NoError(t, ver.AddIssuer(issuer, []string{"test-app"}, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}))
	token, err := embedded.MintRemoteApplicationAccessToken(ctx, signer, authkit.RemoteApplicationAccessParams{
		Issuer: issuer, Audiences: []string{"test-app"}, TTL: time.Minute,
	})
	require.NoError(t, err)

	cl, err := ver.Verify(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, ra.ID, cl.RemoteApplicationID)

	app.Enabled = false
	_, err = coreSvc.UpsertRemoteApplication(ctx, app)
	require.NoError(t, err)

	_, err = ver.Verify(context.Background(), token)
	require.Error(t, err, "a disabled application's token must fail closed immediately")

	_, err = coreSvc.GetRemoteApplication(ctx, issuer)
	require.ErrorIs(t, err, authkit.ErrRemoteApplicationNotFound, "issuer lookups are verification-facing and must not see disabled rows")
	bySlug, err := coreSvc.GetRemoteApplicationBySlug(ctx, app.Slug)
	require.NoError(t, err, "admin reads by slug still see the disabled row")
	require.False(t, bySlug.Enabled)
}
