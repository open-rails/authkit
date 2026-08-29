package authhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

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

func deviceKeyTestServer(t *testing.T) (*Service, *captureEmailSender) {
	t.Helper()
	pool := newServerTestPool(t)
	_, err := authkitmigrate.New(pool, nil).Migrate(context.Background())
	require.NoError(t, err)
	sender := &captureEmailSender{}
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithEmailSender(sender)), WithoutRateLimiter())
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
	var token deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &token))
	require.NotEmpty(t, token.AccessToken)
	require.Equal(t, "Bearer", token.TokenType)
	require.NotEmpty(t, token.DeviceKey.ID)
	return token
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
	require.ElementsMatch(t, []any{"device_key"}, claims["amr"])
	require.Equal(t, embedded.AssuranceLevelPassword, claims["acr"])
	require.Equal(t, enrolled.DeviceKey.ID, claims["device_key_id"])
	require.NotEmpty(t, claims["auth_time"])
	require.NotEmpty(t, claims["sub"])
	require.NotContains(t, claims, "sid")

	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.True(t, user.EmailVerified)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })
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
	var loggedIn deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &loggedIn))
	require.Equal(t, enrolled.DeviceKey.ID, loggedIn.DeviceKey.ID)
	require.NotEmpty(t, loggedIn.AccessToken)
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
