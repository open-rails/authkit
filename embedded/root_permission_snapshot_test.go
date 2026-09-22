package embedded

import (
	"context"
	"crypto"
	"fmt"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/rootsnapshot"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func TestRootPermissionSnapshotIssuanceFailureAndExtras(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	signer, err := jwtkit.NewRSASigner(2048, "snapshot")
	require.NoError(t, err)
	permissions := make([]string, rootsnapshot.MaxGrants+1)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("root:resource%d:read", i)
	}
	cfg := Config{Token: TokenConfig{Issuer: "https://snapshot.test", IssuedAudiences: []string{"app"}}, TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled}, Keys: KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}}, RBAC: []PersonaDef{IntrinsicRootPersona(RoleDef{Name: "oversized", Permissions: permissions})}}
	cfg.Ephemeral.AllowMemory = true
	runtime, err := New(cfg, Deps{Postgres: pg.Pool, River: RiverFromHost()})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime.Client()
	user, err := client.CreateUser(t.Context(), "snapshot-failure@example.test", "snapshot-failure")
	require.NoError(t, err)
	v := verify.NewVerifier()
	require.NoError(t, v.AddIssuer(cfg.Token.Issuer, []string{"app"}, verify.IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	mint := func(extra map[string]any) verify.Claims {
		t.Helper()
		token, _, err := client.MintAccessToken(t.Context(), user.ID, extra)
		require.NoError(t, err)
		claims, err := v.Verify(t.Context(), token)
		require.NoError(t, err)
		return claims
	}
	_, complete := mint(map[string]any{rootsnapshot.Claim: map[string]any{"v": 1, "grants": []string{"root:*"}}}).RootPermissionSnapshot("root:posts:delete")
	require.False(t, complete, "default does not mint snapshots or accept caller extras")
	runtime.engine.cfg.Token.RootPermissionSnapshot = true
	allowed, complete := mint(nil).RootPermissionSnapshot("root:posts:delete")
	require.False(t, allowed)
	require.True(t, complete)
	require.NoError(t, client.OperatorAssignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(user.ID), "oversized"))
	_, complete = mint(nil).RootPermissionSnapshot("root:posts:delete")
	require.False(t, complete, "overflow omits the whole snapshot instead of truncating")
	allowed, err = client.Can(t.Context(), authkit.UserSubject(user.ID), authkit.RootGroup(), authkit.Perm(permissions[0]))
	require.NoError(t, err)
	require.True(t, allowed, "live Can remains usable when the snapshot is unavailable")
	_, err = pg.Pool.Exec(t.Context(), "ALTER TABLE permission_groups RENAME TO unavailable_permission_groups")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := pg.Pool.Exec(cleanup, "ALTER TABLE unavailable_permission_groups RENAME TO permission_groups")
		require.NoError(t, err)
	})
	_, complete = mint(nil).RootPermissionSnapshot("root:posts:delete")
	require.False(t, complete, "authorization lookup failure must not become an empty complete grant list")
}
