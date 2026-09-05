package authcore

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestRemoteApplicationIssuerOwnershipConcurrent(t *testing.T) {
	pool := testdb.ScratchPostgres(t).Pool
	ctx := context.Background()
	svc, err := newFromConfig(Config{Keys: KeysConfig{AllowEphemeralDevKeys: true}, Token: TokenConfig{Issuer: "https://platform.example", IssuedAudiences: []string{"test"}, ExpectedAudiences: []string{"test"}}, RBAC: []PersonaDef{{Name: "merchant", Parent: RootPersona}}}, pool)
	require.NoError(t, err)
	require.NoError(t, svc.SeedPermissionGroupContainment(ctx))
	root, err := svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	groups := [2]string{}
	for i := range groups {
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO profiles.permission_groups(persona, parent_id, instance_slug) VALUES('merchant', $1::uuid, $2) RETURNING id::text`, root, fmt.Sprintf("issuer-owner-%d", i)).Scan(&groups[i]))
	}
	for _, direct := range []bool{false, true} {
		t.Run(fmt.Sprintf("direct_query=%t", direct), func(t *testing.T) {
			for round := range 8 {
				issuer := fmt.Sprintf("https://issuer-%t-%d.example", direct, round)
				start := make(chan struct{})
				type result struct {
					owner int
					err   error
				}
				results := make(chan result, 2)
				for i, group := range groups {
					go func() {
						<-start
						in := RemoteApplication{Slug: fmt.Sprintf("issuer-%t-%d-%d", direct, round, i), PermissionGroupID: group, Issuer: issuer, JWKSURI: fmt.Sprintf("https://keys-%d.example/jwks.json", i), Enabled: true}
						var err error
						if direct {
							_, err = svc.q.RemoteApplicationUpsert(ctx, db.RemoteApplicationUpsertParams{Slug: in.Slug, PermissionGroupID: &group, Issuer: issuer, JwksUri: in.JWKSURI, Mode: RemoteAppModeJWKS, Enabled: true})
						} else {
							_, err = svc.UpsertRemoteApplication(ctx, in)
						}
						results <- result{owner: i, err: err}
					}()
				}
				close(start)
				winner := -1
				for range groups {
					r := <-results
					if r.err == nil {
						require.Equal(t, -1, winner, "both groups claimed issuer %s", issuer)
						winner = r.owner
					} else if direct {
						require.ErrorIs(t, r.err, pgx.ErrNoRows)
					} else {
						require.ErrorIs(t, r.err, ErrRemoteApplicationIssuerConflict)
					}
				}
				require.NotEqual(t, -1, winner)
				stored, err := svc.GetRemoteApplication(ctx, issuer)
				require.NoError(t, err)
				require.Equal(t, groups[winner], stored.PermissionGroupID)
				require.Equal(t, fmt.Sprintf("https://keys-%d.example/jwks.json", winner), stored.JWKSURI)
			}
		})
	}
}
