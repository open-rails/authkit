package embedded

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestFactorEnrollmentConcurrentFirstFactor(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	for _, sameMethod := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_method_%v", sameMethod), func(t *testing.T) {
			username := fmt.Sprintf("firstfactor%d", time.Now().UnixNano())
			user, err := svc.CreateUser(ctx, username+"@test.example", username)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
			start := make(chan struct{})
			var wg sync.WaitGroup
			results := make([][]string, 2)
			errs := make([]error, 2)
			for i := range 2 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					method := "email"
					phone := "+15551234567"
					if i == 1 && !sameMethod {
						method = "sms"
					}
					results[i], errs[i] = svc.Enable2FA(ctx, user.ID, method, &phone, FirstFactorOnly)
				}(i)
			}
			close(start)
			wg.Wait()
			successes := 0
			var issuedCodes []string
			for i, err := range errs {
				if err == nil {
					successes++
					issuedCodes = results[i]
				} else {
					require.ErrorIs(t, err, authkit.ErrTwoFAFactorExists)
				}
			}
			require.Equal(t, 1, successes)
			require.Len(t, issuedCodes, 10)
			settings, err := svc.Get2FASettings(ctx, user.ID)
			require.NoError(t, err)
			require.Len(t, settings.Factors, 1)
			require.True(t, settings.Factors[0].IsDefault)
			for i, code := range issuedCodes {
				require.Equal(t, sha256Hex(code), settings.BackupCodes[i])
			}

			// Authenticated management may add another method, but cannot replace the winner.
			phone := "+15559876543"
			_, err = svc.Enable2FADefault(ctx, user.ID, settings.Factors[0].Method, &phone, AllowAdditionalFactors)
			require.ErrorIs(t, err, authkit.ErrTwoFAFactorExists)
			preserved, err := svc.Get2FASettings(ctx, user.ID)
			require.NoError(t, err)
			require.Equal(t, settings, preserved)
		})
	}
}
