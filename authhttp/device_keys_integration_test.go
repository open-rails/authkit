package authhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
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
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	DeviceKey   struct {
		ID string `json:"id"`
	}
}

// UnmarshalJSON lifts {"token_set": ..., "device_key": ...} (#313) into the flat fields.
func (b *deviceKeyTokenBody) UnmarshalJSON(raw []byte) error {
	var env struct {
		TokenSet  authkit.TokenSet `json:"token_set"`
		DeviceKey struct {
			ID string `json:"id"`
		} `json:"device_key"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	b.AccessToken, b.TokenType, b.ExpiresIn, b.DeviceKey = env.TokenSet.AccessToken, env.TokenSet.TokenType, env.TokenSet.ExpiresIn, env.DeviceKey
	return nil
}

func deviceKeyTestServer(t *testing.T, engineOpts ...coreOpt) (*Service, *captureEmailSender) {
	t.Helper()
	return deviceKeyTestServerWithConfig(t, newServerTestConfig(), engineOpts...)
}

func deviceKeyTestServerWithConfig(t *testing.T, cfg embedded.Config, engineOpts ...coreOpt) (*Service, *captureEmailSender) {
	t.Helper()
	pool := testdb.Pool(t)
	sender := &captureEmailSender{}
	opts := append([]coreOpt{withEmailSender(sender)}, engineOpts...)
	srv, err := New(newServerClient(t, cfg, pool, opts...), workflowHTTPConfig())
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
	require.ElementsMatch(t, []string{"token_set", "device_key"}, mapKeys(body))
	var tokenSet map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body["token_set"], &tokenSet))
	require.ElementsMatch(t, []string{"access_token", "token_type", "expires_in"}, mapKeys(tokenSet))
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

func TestNativeCredentialWorkflow(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		t.Run("passkey", func(t *testing.T) { testPasskeyFullCeremonyAndAssurance(t, store) })
		t.Run("device_key", func(t *testing.T) { testDeviceKeyLifecycle(t, store) })
	})
}

func testDeviceKeyLifecycle(t *testing.T, store ephemeralStore) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t, store.engineOpts()...)
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
	require.Empty(t, sender.deviceKeyNotices(), "new accounts have no existing owner to notify")
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

	status, _ = postDeviceJSON(t, srv, "/device-keys/login/finish", map[string]any{
		"challenge_id": unknown.ChallengeID,
		"signature":    signDeviceChallenge(t, privateKey, testDeviceLoginDomain, unknown.Challenge),
	})
	require.Equal(t, http.StatusUnauthorized, status)
	first, firstPrivate := enrolled, privateKey
	secondPublic, secondPrivate := newDeviceKey(t)
	second := finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, email, secondPublic), secondPrivate)
	require.Equal(t, claims["sub"], unverifiedAccessClaims(t, second.AccessToken)["sub"])
	require.NotEqual(t, first.DeviceKey.ID, second.DeviceKey.ID)
	require.Equal(t, []string{email}, sender.deviceKeyNotices(), "an independent machine notifies the existing owner")
	listed := serveAuthJSON(srv, http.MethodGet, "/device-keys", "", second.AccessToken)
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	var list struct {
		Data []deviceKeyListResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(listed.Body.Bytes(), &list))
	require.Len(t, list.Data, 2)
	current := 0
	for _, key := range list.Data {
		if key.Current {
			current++
			require.Equal(t, second.DeviceKey.ID, key.ID)
		}
	}
	require.Equal(t, 1, current)

	// An ordinary device-key token is not a recovery-root proof.
	loggedIn = loginDeviceKey(t, srv, second.DeviceKey.ID, secondPrivate)
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
	require.Equal(t, http.StatusNoContent, revoked.Code, revoked.Body.String())
	var live int
	require.NoError(t, srv.svc.Postgres().QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1 AND revoked_at IS NULL`, user.ID).Scan(&live))
	require.Equal(t, 1, live)

	// The replaced machine can no longer mint a token; the kept machine can.
	status, raw = postDeviceJSON(t, srv, "/device-keys/login/begin", map[string]any{"device_key_id": first.DeviceKey.ID})
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
	require.Equal(t, http.StatusNoContent, logout.Code, logout.Body.String())
	retry := serveAuthJSON(srv, http.MethodDelete, logoutPath, "", kept.AccessToken)
	require.Equal(t, http.StatusNoContent, retry.Code, retry.Body.String())
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
