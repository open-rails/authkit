package authhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

const (
	testDeviceEnrollmentDomain = "authkit.device-key-enrollment/1"
	testDeviceLoginDomain      = "authkit.device-key-login/1"
)

type deviceKeyChallengeBody struct {
	EnrollmentID string    `json:"enrollment_id"`
	ChallengeID  string    `json:"challenge_id"`
	Challenge    string    `json:"challenge"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type deviceKeyTokenBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   string `json:"expires_at"`
	DeviceKey   struct {
		ID string `json:"id"`
	} `json:"device_key"`
}

func deviceKeyTestServer(t *testing.T, engineOpts ...embedded.Option) (*Service, *captureEmailSender) {
	t.Helper()
	pool := newServerTestPool(t)
	_, err := authkitmigrate.New(pool, nil).Migrate(context.Background())
	require.NoError(t, err)
	sender := &captureEmailSender{}
	opts := append([]embedded.Option{embedded.WithEmailSender(sender)}, engineOpts...)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, opts...), WithoutRateLimiter())
	require.NoError(t, err)
	return srv, sender
}

func newDeviceKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(publicKey), privateKey
}

func signDeviceChallenge(t *testing.T, privateKey ed25519.PrivateKey, domain, encodedChallenge string) string {
	t.Helper()
	challenge, err := base64.RawURLEncoding.DecodeString(encodedChallenge)
	require.NoError(t, err)
	require.Len(t, challenge, 32)
	message := append(append([]byte(domain), 0), challenge...)
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
}

func postDeviceJSON(t *testing.T, srv *Service, path string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	w := serveJSON(srv, http.MethodPost, path, string(raw))
	return w.Code, w.Body.Bytes()
}

func beginDeviceEnrollment(t *testing.T, srv *Service, email, publicKey string) deviceKeyChallengeBody {
	t.Helper()
	status, raw := postDeviceJSON(t, srv, "/device-keys/enroll/begin", map[string]any{
		"email": email, "public_key": publicKey, "label": "test machine",
	})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var challenge deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(raw, &challenge))
	require.NotEmpty(t, challenge.EnrollmentID)
	require.NotEmpty(t, challenge.Challenge)
	require.WithinDuration(t, time.Now().Add(10*time.Minute), challenge.ExpiresAt, 10*time.Second)
	return challenge
}

func finishDeviceEnrollment(t *testing.T, srv *Service, sender *captureEmailSender, challenge deviceKeyChallengeBody, privateKey ed25519.PrivateKey) deviceKeyTokenBody {
	t.Helper()
	status, raw := postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
		"enrollment_id": challenge.EnrollmentID,
		"code":          sender.verificationCode(t),
		"signature":     signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, challenge.Challenge),
	})
	require.Equal(t, http.StatusOK, status, string(raw))
	requireDeviceKeyTokenShape(t, raw)
	var token deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &token))
	require.NotEmpty(t, token.AccessToken)
	require.Equal(t, "Bearer", token.TokenType)
	require.NotEmpty(t, token.DeviceKey.ID)
	return token
}

func requireDeviceKeyTokenShape(t *testing.T, raw []byte) {
	t.Helper()
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &body))
	require.ElementsMatch(t, []string{"access_token", "token_type", "expires_at", "device_key"}, mapKeys(body))
	var device map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body["device_key"], &device))
	require.ElementsMatch(t, []string{"id", "label", "created_at"}, mapKeys(device))
}

func mapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func TestDeviceKeyEmailEnrollmentAndRefreshlessLogin(t *testing.T) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t)
	pool := srv.svc.Postgres()
	email := uniqueEmail("device-key")
	publicKey, privateKey := newDeviceKey(t)

	enrollment := beginDeviceEnrollment(t, srv, email, publicKey)
	// One typo does not burn the ceremony; the bounded attempt counter does.
	wrongCode := "000000"
	if sender.verificationCode(t) == wrongCode {
		wrongCode = "000001"
	}
	status, raw := postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
		"enrollment_id": enrollment.EnrollmentID,
		"code":          wrongCode,
		"signature":     signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, enrollment.Challenge),
	})
	require.Equal(t, http.StatusBadRequest, status, string(raw))

	enrolled := finishDeviceEnrollment(t, srv, sender, enrollment, privateKey)
	claims := unverifiedAccessClaims(t, enrolled.AccessToken)
	require.ElementsMatch(t, []any{"device_key", "email"}, claims["amr"])
	require.Equal(t, embedded.AssuranceLevelPassword, claims["acr"])
	require.Equal(t, enrolled.DeviceKey.ID, claims["device_key_id"])
	require.NotEmpty(t, claims["auth_time"])
	require.NotEmpty(t, claims["sub"])
	require.NotContains(t, claims, "sid")

	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.True(t, user.EmailVerified)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
	meResponse := serveAuthJSON(srv, http.MethodGet, "/me", "", enrolled.AccessToken)
	require.Equal(t, http.StatusOK, meResponse.Code, meResponse.Body.String())
	var me struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	require.NoError(t, json.Unmarshal(meResponse.Body.Bytes(), &me))
	require.Equal(t, user.ID, me.ID)
	require.Empty(t, me.Username)
	var refreshSessions int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1`, user.ID).Scan(&refreshSessions))
	require.Zero(t, refreshSessions)

	// Enrollment is single use.
	status, _ = postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
		"enrollment_id": enrollment.EnrollmentID,
		"code":          sender.verificationCode(t),
		"signature":     signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, enrollment.Challenge),
	})
	require.Equal(t, http.StatusBadRequest, status)

	status, raw = postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": enrolled.DeviceKey.ID})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var login deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(raw, &login))

	// Cross-purpose signatures are rejected without consuming the valid challenge.
	status, _ = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": login.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, login.Challenge),
	})
	require.Equal(t, http.StatusUnauthorized, status)

	status, raw = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": login.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, login.Challenge),
	})
	require.Equal(t, http.StatusOK, status, string(raw))
	requireDeviceKeyTokenShape(t, raw)
	var loggedIn deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &loggedIn))
	require.Equal(t, enrolled.DeviceKey.ID, loggedIn.DeviceKey.ID)
	require.NotEmpty(t, loggedIn.AccessToken)
	require.ElementsMatch(t, []any{"device_key"}, unverifiedAccessClaims(t, loggedIn.AccessToken)["amr"])
	require.NotContains(t, unverifiedAccessClaims(t, loggedIn.AccessToken), "sid")

	// Login challenge is single use.
	status, _ = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": login.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, login.Challenge),
	})
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestDeviceKeyLoginBeginDoesNotRevealKnownKey(t *testing.T) {
	srv, sender := deviceKeyTestServer(t)
	email := uniqueEmail("device-key-enum")
	publicKey, privateKey := newDeviceKey(t)
	enrolled := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, publicKey), privateKey)
	user, err := srv.svc.GetUserByEmail(context.Background(), email)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1`, user.ID)
	})

	knownStatus, knownRaw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": enrolled.DeviceKey.ID})
	unknownStatus, unknownRaw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": "018f6f74-9f0c-7b27-8000-000000000001"})
	require.Equal(t, http.StatusAccepted, knownStatus)
	require.Equal(t, knownStatus, unknownStatus)
	var known, unknown deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(knownRaw, &known))
	require.NoError(t, json.Unmarshal(unknownRaw, &unknown))
	require.Len(t, known.ChallengeID, len(unknown.ChallengeID))
	require.Len(t, known.Challenge, len(unknown.Challenge))
	require.False(t, known.ExpiresAt.IsZero())
	require.False(t, unknown.ExpiresAt.IsZero())

	status, _ := postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": unknown.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, unknown.Challenge),
	})
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestDeviceKeyEmailEnrollmentAddsIndependentMachineToExistingAccount(t *testing.T) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t)
	email := uniqueEmail("device-key-second")
	firstPublic, firstPrivate := newDeviceKey(t)
	first := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, firstPublic), firstPrivate)
	secondPublic, secondPrivate := newDeviceKey(t)
	second := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, secondPublic), secondPrivate)

	firstClaims := unverifiedAccessClaims(t, first.AccessToken)
	secondClaims := unverifiedAccessClaims(t, second.AccessToken)
	require.Equal(t, firstClaims["sub"], secondClaims["sub"])
	require.NotEqual(t, first.DeviceKey.ID, second.DeviceKey.ID)

	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
	var keys int
	require.NoError(t, srv.svc.Postgres().QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1 AND revoked_at IS NULL`, user.ID).Scan(&keys))
	require.Equal(t, 2, keys)
}

func loginDeviceKey(t *testing.T, srv *Service, id string, privateKey ed25519.PrivateKey) deviceKeyTokenBody {
	t.Helper()
	status, raw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": id})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var challenge deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(raw, &challenge))
	status, raw = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": challenge.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, challenge.Challenge),
	})
	require.Equal(t, http.StatusOK, status, string(raw))
	var token deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &token))
	return token
}

func TestDeviceKeyManagementRevokesExactlyTheRequestedMachines(t *testing.T) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t)
	email := uniqueEmail("device-key-management")
	firstPublic, firstPrivate := newDeviceKey(t)
	first := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, firstPublic), firstPrivate)
	secondPublic, secondPrivate := newDeviceKey(t)
	second := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, secondPublic), secondPrivate)
	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })

	listed := serveAuthJSON(srv, http.MethodGet, "/device-keys", "", second.AccessToken)
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	var list struct {
		DeviceKeys []deviceKeyListResponse `json:"device_keys"`
	}
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &list))
	require.Len(t, list.DeviceKeys, 2)
	current := 0
	for _, key := range list.DeviceKeys {
		if key.Current {
			current++
			require.Equal(t, second.DeviceKey.ID, key.ID)
		}
	}
	require.Equal(t, 1, current)

	// An ordinary device-key token is not a recovery-root proof.
	loggedIn := loginDeviceKey(t, srv, second.DeviceKey.ID, secondPrivate)
	refused := serveAuthJSON(srv, http.MethodPost, "/device-keys/revoke-others", `{}`, loggedIn.AccessToken)
	require.Equal(t, http.StatusForbidden, refused.Code, refused.Body.String())

	// Re-enrolling the exact active key is an email proof, not a new machine.
	proof := finishDeviceEnrollment(t, srv, sender,
		beginDeviceEnrollment(t, srv, email, secondPublic), secondPrivate)
	require.Equal(t, second.DeviceKey.ID, proof.DeviceKey.ID)
	var total int
	require.NoError(t, srv.svc.Postgres().QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1`, user.ID).Scan(&total))
	require.Equal(t, 2, total)
	revoked := serveAuthJSON(srv, http.MethodPost, "/device-keys/revoke-others", `{}`, proof.AccessToken)
	require.Equal(t, http.StatusOK, revoked.Code, revoked.Body.String())
	var live int
	require.NoError(t, srv.svc.Postgres().QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1 AND revoked_at IS NULL`, user.ID).Scan(&live))
	require.Equal(t, 1, live)

	// The replaced machine can no longer mint a token; the kept machine can.
	status, raw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": first.DeviceKey.ID})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var firstChallenge deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(raw, &firstChallenge))
	status, _ = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": firstChallenge.ChallengeID,
		"signature":    signDeviceChallenge(t, firstPrivate, testDeviceLoginDomain, firstChallenge.Challenge),
	})
	require.Equal(t, http.StatusUnauthorized, status)
	kept := loginDeviceKey(t, srv, second.DeviceKey.ID, secondPrivate)

	// Logout is retry-safe: the revoked key's residual token can only confirm
	// revocation of itself, never mutate another machine.
	logoutPath := "/device-keys/" + second.DeviceKey.ID
	logout := serveAuthJSON(srv, http.MethodDelete, logoutPath, "", kept.AccessToken)
	require.Equal(t, http.StatusOK, logout.Code, logout.Body.String())
	retry := serveAuthJSON(srv, http.MethodDelete, logoutPath, "", kept.AccessToken)
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	attack := serveAuthJSON(srv, http.MethodDelete, "/device-keys/"+first.DeviceKey.ID, "", kept.AccessToken)
	require.Equal(t, http.StatusUnauthorized, attack.Code, attack.Body.String())

	// Tombstoned key bytes cannot be reactivated through email recovery.
	reenroll := beginDeviceEnrollment(t, srv, email, secondPublic)
	status, _ = postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
		"enrollment_id": reenroll.EnrollmentID,
		"code":          sender.verificationCode(t),
		"signature":     signDeviceChallenge(t, secondPrivate, testDeviceEnrollmentDomain, reenroll.Challenge),
	})
	require.Equal(t, http.StatusBadRequest, status)
}

func TestDeviceKeyLoginConcurrentFinishAcceptsOnce(t *testing.T) {
	forEachStore(t, testDeviceKeyLoginConcurrentFinishAcceptsOnce)
}

func testDeviceKeyLoginConcurrentFinishAcceptsOnce(t *testing.T, store ephemeralStore) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t, store.engineOpts()...)
	email := uniqueEmail("device-key-login-race")
	publicKey, privateKey := newDeviceKey(t)
	enrolled := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, publicKey), privateKey)
	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })

	status, raw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": enrolled.DeviceKey.ID})
	require.Equal(t, http.StatusAccepted, status, string(raw))
	var challenge deviceKeyChallengeBody
	require.NoError(t, json.Unmarshal(raw, &challenge))
	body, err := json.Marshal(map[string]any{
		"challenge_id": challenge.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, challenge.Challenge),
	})
	require.NoError(t, err)

	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- serveJSON(srv, http.MethodPost, "/device-keys/login/finish", string(body)).Code
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	require.Equal(t, 1, counts[http.StatusOK])
	require.Equal(t, 1, counts[http.StatusUnauthorized])
}

func TestDeviceKeyLoginRefusesBannedAndDeletedUsers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(context.Context, *Service, string) error
	}{
		{name: "banned", mutate: func(ctx context.Context, srv *Service, userID string) error {
			return srv.svc.BanUser(ctx, userID, nil, nil, userID)
		}},
		{name: "deleted", mutate: func(ctx context.Context, srv *Service, userID string) error {
			return srv.svc.SoftDeleteUser(ctx, userID)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			srv, sender := deviceKeyTestServer(t)
			email := uniqueEmail("device-key-" + test.name)
			publicKey, privateKey := newDeviceKey(t)
			enrolled := finishDeviceEnrollment(t, srv, sender,
				beginDeviceEnrollment(t, srv, email, publicKey), privateKey)
			user, err := srv.svc.GetUserByEmail(ctx, email)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })

			status, raw := postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": enrolled.DeviceKey.ID})
			require.Equal(t, http.StatusAccepted, status, string(raw))
			var challenge deviceKeyChallengeBody
			require.NoError(t, json.Unmarshal(raw, &challenge))
			require.NoError(t, test.mutate(ctx, srv, user.ID))
			// #286: ban / soft delete revoke the key itself, so the device list agrees.
			var revoked bool
			require.NoError(t, srv.svc.Postgres().QueryRow(ctx,
				`SELECT revoked_at IS NOT NULL FROM profiles.user_device_keys WHERE id=$1`, enrolled.DeviceKey.ID).Scan(&revoked))
			require.True(t, revoked, "device key must be revoked by %s", test.name)
			status, _ = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
				"challenge_id": challenge.ChallengeID,
				"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, challenge.Challenge),
			})
			require.Equal(t, http.StatusUnauthorized, status)
		})
	}
}

func TestDeviceKeyEnrollmentAttemptCapInvalidatesCeremony(t *testing.T) {
	srv, sender := deviceKeyTestServer(t)
	email := uniqueEmail("device-key-attempts")
	publicKey, privateKey := newDeviceKey(t)
	enrollment := beginDeviceEnrollment(t, srv, email, publicKey)
	signature := signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, enrollment.Challenge)
	wrongCode := "000000"
	if sender.verificationCode(t) == wrongCode {
		wrongCode = "000001"
	}
	for range 5 {
		status, _ := postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
			"enrollment_id": enrollment.EnrollmentID, "code": wrongCode, "signature": signature,
		})
		require.Equal(t, http.StatusBadRequest, status)
	}
	status, _ := postDeviceJSON(t, srv, "/device-keys/enroll/finish", map[string]any{
		"enrollment_id": enrollment.EnrollmentID, "code": sender.verificationCode(t), "signature": signature,
	})
	require.Equal(t, http.StatusBadRequest, status)
}

func TestDeviceKeyEnrollmentConcurrentFinishAcceptsOnce(t *testing.T) {
	srv, sender := deviceKeyTestServer(t)
	email := uniqueEmail("device-key-race")
	publicKey, privateKey := newDeviceKey(t)
	enrollment := beginDeviceEnrollment(t, srv, email, publicKey)
	body := map[string]any{
		"enrollment_id": enrollment.EnrollmentID,
		"code":          sender.verificationCode(t),
		"signature":     signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, enrollment.Challenge),
	}
	rawBody, err := json.Marshal(body)
	require.NoError(t, err)

	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := serveJSON(srv, http.MethodPost, "/device-keys/enroll/finish", string(rawBody))
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	require.Equal(t, 1, counts[http.StatusOK])
	require.Equal(t, 1, counts[http.StatusBadRequest])

	user, err := srv.svc.GetUserByEmail(context.Background(), email)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1`, user.ID)
	})
	var keys int
	require.NoError(t, srv.svc.Postgres().QueryRow(context.Background(), `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1`, user.ID).Scan(&keys))
	require.Equal(t, 1, keys)
}

func TestDeviceKeyEnrollmentWithHostSearchPathExcludingPublic(t *testing.T) {
	ctx := context.Background()
	basePool := newServerTestPool(t)
	_, err := authkitmigrate.New(basePool, nil).Migrate(ctx)
	require.NoError(t, err)

	config, err := pgxpool.ParseConfig(os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	require.NoError(t, err)
	config.ConnConfig.RuntimeParams["search_path"] = "hub_v2"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var searchPath string
	require.NoError(t, pool.QueryRow(ctx, `SHOW search_path`).Scan(&searchPath))
	require.Equal(t, "hub_v2", searchPath)

	sender := &captureEmailSender{}
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithEmailSender(sender)), WithoutRateLimiter())
	require.NoError(t, err)
	email := uniqueEmail("device-key-search-path")
	publicKey, privateKey := newDeviceKey(t)
	result := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, publicKey), privateKey)
	require.NotEmpty(t, result.AccessToken)
	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = basePool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
}
