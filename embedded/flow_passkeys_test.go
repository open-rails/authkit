package embedded

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
)

const passkeyOrigin = "https://example.com"

func passkeyTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Keys:         testKeys(t),
		Token:        TokenConfig{Issuer: passkeyOrigin, IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone},
		Ephemeral:    EphemeralConfig{AllowMemory: true},
		Passkeys:     PasskeyConfig{RPID: "example.com", RPDisplayName: "Example", Origins: []string{passkeyOrigin}},
	}
}

// forEachPasskeyStore proves every single-use pin on the memory store and on
// Redis (AUTHKIT_TEST_REDIS_URL; always set in CI).
func forEachPasskeyStore(t *testing.T, fn func(t *testing.T, pool *pgxpool.Pool, deps Deps)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		pool := testdb.Pool(t)
		fn(t, pool, Deps{Postgres: pool})
	})
	t.Run("redis", func(t *testing.T) {
		pool := testdb.Pool(t)
		fn(t, pool, Deps{Postgres: pool, Redis: testdb.ScratchRedis(t)})
	})
}

func newPasskeyClient(t *testing.T, cfg Config, deps Deps) *Client {
	t.Helper()
	c, err := New(cfg, deps)
	require.NoError(t, err)
	return c
}

func newPasskeyUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, c *Client) *authkit.User {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	u, err := c.CreateUser(ctx, fmt.Sprintf("passkey-%s@test.example", suffix), "pk"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	return u
}

func registerPasskey(t *testing.T, ctx context.Context, c *Client, userID string, authn *passkeytest.Authenticator) Passkey {
	t.Helper()
	creation, err := c.BeginPasskeyRegistration(ctx, userID)
	require.NoError(t, err)
	p, err := c.FinishPasskeyRegistration(ctx, userID, authn.Register(t, creation))
	require.NoError(t, err)
	return p
}

func sessionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1::uuid`, userID).Scan(&n))
	return n
}

func activePasskeyIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT id FROM profiles.user_passkeys WHERE user_id=$1::uuid AND deleted_at IS NULL ORDER BY created_at, id`, userID)
	require.NoError(t, err)
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}

func userExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) bool {
	t.Helper()
	var exists bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.users WHERE id=$1::uuid)`, userID).Scan(&exists))
	return exists
}

func b64(in []byte) string { return base64.RawURLEncoding.EncodeToString(in) }

// The verification pair returns identity proof only: no session row, no token,
// single-use and purpose-bound ceremonies, and every existing assertion
// protection intact. Passkey login still mints its session on top of it.
func TestPasskeyVerificationProvesIdentityWithoutSession(t *testing.T) {
	forEachPasskeyStore(t, func(t *testing.T, pool *pgxpool.Pool, deps Deps) {
		ctx := context.Background()
		c := newPasskeyClient(t, passkeyTestConfig(t), deps)
		user := newPasskeyUser(t, ctx, pool, c)
		authn := passkeytest.New(t, passkeyOrigin)
		created := registerPasskey(t, ctx, c, user.ID, authn)

		assertion, err := c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		require.Empty(t, assertion.Response.AllowedCredentials)
		require.Equal(t, protocol.VerificationRequired, assertion.Response.UserVerification)

		response := authn.Assert(t, assertion, 1)
		verified, err := c.FinishDiscoverablePasskeyVerification(ctx, response)
		require.NoError(t, err)
		require.Equal(t, VerifiedPasskey{UserID: user.ID, PasskeyID: created.ID, CredentialID: b64(authn.CredentialID), BackupEligible: true, BackupState: true}, verified)
		require.Zero(t, sessionCount(t, ctx, pool, user.ID))
		var lastUsed *time.Time
		require.NoError(t, pool.QueryRow(ctx, `SELECT last_used_at FROM profiles.user_passkeys WHERE id=$1::uuid`, created.ID).Scan(&lastUsed))
		require.NotNil(t, lastUsed)

		_, err = c.FinishDiscoverablePasskeyVerification(ctx, response)
		require.Error(t, err, "replayed assertion must fail: the ceremony was consumed")

		// A verification ceremony can never be finished as a login (no session
		// mint), and a login ceremony can never be finished as a verification.
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishPasskeyLogin(ctx, authn.Assert(t, assertion, 2), "test", nil)
		require.Error(t, err)
		require.Zero(t, sessionCount(t, ctx, pool, user.ID))
		assertion, err = c.BeginPasskeyLogin(ctx, "")
		require.NoError(t, err)
		crossed := authn.Assert(t, assertion, 3)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, crossed)
		require.Error(t, err)
		_, err = c.FinishPasskeyLogin(ctx, crossed, "test", nil)
		require.Error(t, err, "a cross-purpose attempt burns the ceremony")
		require.Zero(t, sessionCount(t, ctx, pool, user.ID))

		assertion, err = c.BeginPasskeyLogin(ctx, "")
		require.NoError(t, err)
		login, err := c.FinishPasskeyLogin(ctx, authn.Assert(t, assertion, 4), "test", nil)
		require.NoError(t, err)
		require.Equal(t, user.ID, login.UserID)
		require.NotEmpty(t, login.AccessToken)
		require.NotEmpty(t, login.RefreshToken)
		require.NotEmpty(t, login.SessionID)
		require.Equal(t, 1, sessionCount(t, ctx, pool, user.ID))

		wrongOrigin := *authn
		wrongOrigin.Origin = "https://evil.example.com"
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, wrongOrigin.Assert(t, assertion, 5))
		require.Error(t, err)

		noUV := *authn
		noUV.UserVerified = false
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, noUV.Assert(t, assertion, 5))
		require.Error(t, err)

		wrongRP := *authn
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, wrongRP.Assertion(t, "evil.example.com", assertion.Response.Challenge.String(), 5))
		require.Error(t, err)

		stranger := passkeytest.New(t, passkeyOrigin)
		stranger.UserHandle = authn.UserHandle
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, stranger.Assert(t, assertion, 5))
		require.Error(t, err, "unknown credential under a known handle")

		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, authn.Assert(t, assertion, 2))
		require.ErrorIs(t, err, authkit.ErrPasskeyCloneDetected, "counter regression after 4")

		_, err = pool.Exec(ctx, `UPDATE profiles.users SET banned_at=now() WHERE id=$1::uuid`, user.ID)
		require.NoError(t, err)
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, authn.Assert(t, assertion, 6))
		require.ErrorIs(t, err, authkit.ErrUserBanned)

		_, err = pool.Exec(ctx, `UPDATE profiles.users SET banned_at=NULL, deleted_at=now() WHERE id=$1::uuid`, user.ID)
		require.NoError(t, err)
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, authn.Assert(t, assertion, 7))
		require.ErrorIs(t, err, authkit.ErrUserBanned)
		require.Equal(t, 1, sessionCount(t, ctx, pool, user.ID), "only the explicit login ever created a session")
	})
}

// The account pair creates exactly one email-less, username-less, password-less
// user whose uuidv7 is both the user id and the WebAuthn user handle.
func TestPasskeyAccountBootstrapCreatesOnePasskeyOnlyUser(t *testing.T) {
	forEachPasskeyStore(t, func(t *testing.T, pool *pgxpool.Pool, deps Deps) {
		ctx := context.Background()
		c := newPasskeyClient(t, passkeyTestConfig(t), deps)

		pending, err := c.BeginPasskeyAccount(ctx)
		require.NoError(t, err)
		id, err := uuid.Parse(pending.UserID)
		require.NoError(t, err)
		require.Equal(t, uuid.Version(7), id.Version())
		require.Equal(t, id[:], passkeytest.UserHandle(t, pending.Creation.Response.User.ID))
		require.Equal(t, protocol.VerificationRequired, pending.Creation.Response.AuthenticatorSelection.UserVerification)
		require.Equal(t, protocol.ResidentKeyRequirementRequired, pending.Creation.Response.AuthenticatorSelection.ResidentKey)
		require.Equal(t, protocol.PreferNoAttestation, pending.Creation.Response.Attestation)
		require.False(t, userExists(t, ctx, pool, pending.UserID), "begin inserts no user")
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, pending.UserID) })

		authn := passkeytest.New(t, passkeyOrigin)
		response := authn.Register(t, pending.Creation)
		user, passkey, err := c.FinishPasskeyAccount(ctx, response)
		require.NoError(t, err)
		require.Equal(t, pending.UserID, user.ID)
		require.Nil(t, user.Email)
		require.Nil(t, user.Username)
		require.False(t, user.EmailVerified)
		require.Equal(t, pending.UserID, passkey.UserID)
		require.True(t, passkey.BackupEligible)
		require.Equal(t, []string{passkey.ID}, activePasskeyIDs(t, ctx, pool, user.ID))
		var handle []byte
		require.NoError(t, pool.QueryRow(ctx, `SELECT user_handle FROM profiles.user_passkey_handles WHERE user_id=$1::uuid`, user.ID).Scan(&handle))
		require.Equal(t, id[:], handle)
		var passwords int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_passwords WHERE user_id=$1::uuid`, user.ID).Scan(&passwords))
		require.Zero(t, passwords)
		require.Zero(t, sessionCount(t, ctx, pool, user.ID))

		_, _, err = c.FinishPasskeyAccount(ctx, response)
		require.Error(t, err, "replayed finish")
		require.Len(t, activePasskeyIDs(t, ctx, pool, user.ID), 1)

		assertion, err := c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		verified, err := c.FinishDiscoverablePasskeyVerification(ctx, authn.Assert(t, assertion, 1))
		require.NoError(t, err)
		require.Equal(t, user.ID, verified.UserID)
		require.Equal(t, passkey.ID, verified.PasskeyID)

		// An account ceremony cannot attach its credential to an existing user,
		// and a registration ceremony cannot bootstrap an account.
		existing := newPasskeyUser(t, ctx, pool, c)
		other := passkeytest.New(t, passkeyOrigin)
		crossed, err := c.BeginPasskeyAccount(ctx)
		require.NoError(t, err)
		_, err = c.FinishPasskeyRegistration(ctx, existing.ID, other.Register(t, crossed.Creation))
		require.ErrorIs(t, err, authkit.ErrPasskeyNotFound)
		require.False(t, userExists(t, ctx, pool, crossed.UserID))
		require.Empty(t, activePasskeyIDs(t, ctx, pool, existing.ID))
		creation, err := c.BeginPasskeyRegistration(ctx, existing.ID)
		require.NoError(t, err)
		_, _, err = c.FinishPasskeyAccount(ctx, other.Register(t, creation))
		require.Error(t, err)
		require.Empty(t, activePasskeyIDs(t, ctx, pool, existing.ID))

		for name, authn := range map[string]*passkeytest.Authenticator{
			"no user verification": {UserVerified: false},
			"wrong origin":         {Origin: "https://evil.example.com"},
		} {
			fresh := passkeytest.New(t, passkeyOrigin)
			fresh.UserVerified = authn.UserVerified
			if authn.Origin != "" {
				fresh.Origin = authn.Origin
			}
			refused, err := c.BeginPasskeyAccount(ctx)
			require.NoError(t, err)
			_, _, err = c.FinishPasskeyAccount(ctx, fresh.Register(t, refused.Creation))
			require.Error(t, err, name)
			require.False(t, userExists(t, ctx, pool, refused.UserID), name)
		}

		closed := passkeyTestConfig(t)
		closed.Registration.NativeUserMode = RegistrationModeClosed
		_, err = newPasskeyClient(t, closed, deps).BeginPasskeyAccount(ctx)
		require.ErrorIs(t, err, authkit.ErrRegistrationDisabled)

		raced, err := c.BeginPasskeyAccount(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, raced.UserID) })
		racedResponse := passkeytest.New(t, passkeyOrigin).Register(t, raced.Creation)
		var wins int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, _, err := c.FinishPasskeyAccount(ctx, racedResponse); err == nil {
					atomic.AddInt32(&wins, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		require.Equal(t, int32(1), wins, "concurrent finish creates exactly one account")
		require.Len(t, activePasskeyIDs(t, ctx, pool, raced.UserID), 1)
	})
}

// FinishPasskeyReplacement leaves exactly one active passkey on success and the
// prior one untouched on any failure, before or inside the transaction.
func TestPasskeyReplacementIsAtomic(t *testing.T) {
	forEachPasskeyStore(t, func(t *testing.T, pool *pgxpool.Pool, deps Deps) {
		ctx := context.Background()
		c := newPasskeyClient(t, passkeyTestConfig(t), deps)
		user := newPasskeyUser(t, ctx, pool, c)
		first := passkeytest.New(t, passkeyOrigin)
		created := registerPasskey(t, ctx, c, user.ID, first)

		second := passkeytest.New(t, passkeyOrigin)
		creation, err := c.BeginPasskeyRegistration(ctx, user.ID)
		require.NoError(t, err)
		require.Len(t, creation.Response.CredentialExcludeList, 1)
		replaced, err := c.FinishPasskeyReplacement(ctx, user.ID, second.Register(t, creation))
		require.NoError(t, err)
		require.Equal(t, []string{replaced.ID}, activePasskeyIDs(t, ctx, pool, user.ID))
		var tombstoned *time.Time
		require.NoError(t, pool.QueryRow(ctx, `SELECT deleted_at FROM profiles.user_passkeys WHERE id=$1::uuid`, created.ID).Scan(&tombstoned))
		require.NotNil(t, tombstoned)

		assertion, err := c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		_, err = c.FinishDiscoverablePasskeyVerification(ctx, first.Assert(t, assertion, 1))
		require.Error(t, err, "the replaced credential no longer verifies")
		assertion, err = c.BeginDiscoverablePasskeyVerification(ctx)
		require.NoError(t, err)
		verified, err := c.FinishDiscoverablePasskeyVerification(ctx, second.Assert(t, assertion, 1))
		require.NoError(t, err)
		require.Equal(t, replaced.ID, verified.PasskeyID)

		// Failure inside the transaction: the authenticator ignores the exclusion
		// list and re-attests the credential that is already active, so the insert
		// conflicts and the rollback keeps the current passkey.
		creation, err = c.BeginPasskeyRegistration(ctx, user.ID)
		require.NoError(t, err)
		_, err = c.FinishPasskeyReplacement(ctx, user.ID, second.Register(t, creation))
		require.Error(t, err)
		require.Equal(t, []string{replaced.ID}, activePasskeyIDs(t, ctx, pool, user.ID))

		wrongOrigin := passkeytest.New(t, "https://evil.example.com")
		creation, err = c.BeginPasskeyRegistration(ctx, user.ID)
		require.NoError(t, err)
		_, err = c.FinishPasskeyReplacement(ctx, user.ID, wrongOrigin.Register(t, creation))
		require.Error(t, err)
		require.Equal(t, []string{replaced.ID}, activePasskeyIDs(t, ctx, pool, user.ID))

		third := passkeytest.New(t, passkeyOrigin)
		creation, err = c.BeginPasskeyRegistration(ctx, user.ID)
		require.NoError(t, err)
		response := third.Register(t, creation)
		next, err := c.FinishPasskeyReplacement(ctx, user.ID, response)
		require.NoError(t, err)
		require.Equal(t, []string{next.ID}, activePasskeyIDs(t, ctx, pool, user.ID))
		_, err = c.FinishPasskeyReplacement(ctx, user.ID, response)
		require.Error(t, err, "replayed finish")
		require.Equal(t, []string{next.ID}, activePasskeyIDs(t, ctx, pool, user.ID))

		other := newPasskeyUser(t, ctx, pool, c)
		creation, err = c.BeginPasskeyRegistration(ctx, user.ID)
		require.NoError(t, err)
		_, err = c.FinishPasskeyReplacement(ctx, other.ID, passkeytest.New(t, passkeyOrigin).Register(t, creation))
		require.ErrorIs(t, err, authkit.ErrPasskeyNotFound, "a ceremony belongs to the user it was begun for")
		require.Equal(t, []string{next.ID}, activePasskeyIDs(t, ctx, pool, user.ID))
		require.Empty(t, activePasskeyIDs(t, ctx, pool, other.ID))
	})
}
