package authkit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Live MFA policy/state lookups precede the session check. A database outage
// there must remain unavailable rather than masquerade as an invalid session.
func TestMFAAuthenticationDatabaseFailureIsUnavailable(t *testing.T) {
	for _, mode := range []iam.TwoFactorMode{iam.TwoFactorOptional, iam.TwoFactorRequired} {
		t.Run(string(mode), func(t *testing.T) {
			pg := testdb.ScratchPostgres(t)
			cfg, err := pgxpool.ParseConfig(pg.URL)
			require.NoError(t, err)
			cfg.ConnConfig.RuntimeParams["search_path"] = `"profiles", public`
			var down atomic.Bool
			unavailable := errors.New("test: MFA database unavailable")
			cfg.PrepareConn = func(context.Context, *pgx.Conn) (bool, error) {
				if down.Load() {
					return true, unavailable
				}
				return true, nil
			}
			pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			config := testConfig(t)
			config.HTTP = &authkit.HTTPConfig{DirectPeerIP: true}
			signer, err := authkit.New(t.Context(), config, testDeps(pool))
			require.NoError(t, err)
			t.Cleanup(func() { _ = signer.Close(context.Background()) })
			user := authtest.NewUser(t, signer)
			token := authtest.SignIn(t, signer, user).AccessToken
			config.TwoFactor.Mode = mode
			client, err := authkit.New(t.Context(), config, testDeps(pool))
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close(context.Background()) })
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/protected", nil)
				r.Header.Set("Authorization", "Bearer "+token)
				return r
			}
			_, before := client.Authenticator().Authenticate(request())
			if mode == iam.TwoFactorRequired {
				require.ErrorIs(t, before, iam.ErrTwoFAEnrollmentRequired)
			} else {
				require.NoError(t, before)
			}
			down.Store(true)
			_, err = client.Authenticator().Authenticate(request())
			require.ErrorIs(t, err, auth.ErrUnavailable)
			require.NotErrorIs(t, err, auth.ErrUnauthenticated)
			require.ErrorIs(t, err, unavailable, "retain the operator cause")
			refusal := auth.Refuse(request(), err)
			require.Equal(t, http.StatusServiceUnavailable, refusal.Status)
			require.Empty(t, refusal.Header.Get("WWW-Authenticate"), "an outage is not a login challenge")
			down.Store(false)
			_, recovered := client.Authenticator().Authenticate(request())
			if mode == iam.TwoFactorRequired {
				require.ErrorIs(t, recovered, iam.ErrTwoFAEnrollmentRequired)
			} else {
				require.NoError(t, recovered)
			}
		})
	}
}
