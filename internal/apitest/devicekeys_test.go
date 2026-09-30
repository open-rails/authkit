package apitest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
)

// deviceKeyChallenge is the answer of a device-key enrollment or login begin.
type deviceKeyChallenge struct {
	EnrollmentID string    `json:"enrollment_id"`
	ChallengeID  string    `json:"challenge_id"`
	Challenge    string    `json:"challenge"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// deviceKeySession is the answer of a device-key enrollment or login finish.
type deviceKeySession struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	DeviceKey struct {
		ID string `json:"id"`
	} `json:"device_key"`
}

func (f *factorFlow) newDeviceKey() (string, ed25519.PrivateKey) {
	f.t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(f.t, err)
	return base64.RawURLEncoding.EncodeToString(publicKey), privateKey
}

func (f *factorFlow) signDeviceChallenge(key ed25519.PrivateKey, domain, encodedChallenge string) string {
	f.t.Helper()
	challenge, err := base64.RawURLEncoding.DecodeString(encodedChallenge)
	require.NoError(f.t, err)
	require.Len(f.t, challenge, 32)
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, devicekey.Message(domain, challenge)))
}

func (f *factorFlow) beginDeviceEnrollment(email, publicKey string) deviceKeyChallenge {
	f.t.Helper()
	res := f.expect(http.StatusOK, f.post("/device-keys/enroll/begin", map[string]any{"email": email, "public_key": publicKey, "label": "test machine"}))
	var challenge deviceKeyChallenge
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &challenge))
	require.NotEmpty(f.t, challenge.EnrollmentID)
	require.NotEmpty(f.t, challenge.Challenge)
	require.WithinDuration(f.t, time.Now().Add(10*time.Minute), challenge.ExpiresAt, 10*time.Second)
	return challenge
}

// finishDeviceEnrollment answers challenge with the code emailed to email and
// the key's signature, and checks the session's shape.
func (f *factorFlow) finishDeviceEnrollment(email string, challenge deviceKeyChallenge, key ed25519.PrivateKey) deviceKeySession {
	f.t.Helper()
	res := f.expect(http.StatusOK, f.post("/device-keys/enroll/finish", map[string]any{
		"enrollment_id": challenge.EnrollmentID,
		"code":          f.code(iam.MessageVerification, email),
		"signature":     f.signDeviceChallenge(key, devicekey.EnrollmentDomain, challenge.Challenge),
	}))
	return f.deviceKeySession(res)
}

// deviceKeySession decodes a finish answer after checking it is a complete
// AuthResult: a token set without a refresh token, the account, and the
// current device key.
func (f *factorFlow) deviceKeySession(res authAnswer) deviceKeySession {
	f.t.Helper()
	res.signedIn(f.t)
	require.NotNil(f.t, res.DeviceKey, res.raw)
	require.Nil(f.t, res.ReturnTo)
	var body map[string]json.RawMessage
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &body))
	var tokenSet map[string]json.RawMessage
	require.NoError(f.t, json.Unmarshal(body["token_set"], &tokenSet))
	require.ElementsMatch(f.t, []string{"access_token", "token_type", "expires_in", "refresh_token"}, slices.Collect(maps.Keys(tokenSet)))
	require.JSONEq(f.t, "null", string(tokenSet["refresh_token"]), "a device key signs in without a refresh token")
	var device map[string]json.RawMessage
	require.NoError(f.t, json.Unmarshal(body["device_key"], &device))
	require.ElementsMatch(f.t, []string{"id", "label", "public_key", "created_at", "last_used_at", "revoked_at", "current"}, slices.Collect(maps.Keys(device)), "the device key is iam.DeviceKey")
	require.JSONEq(f.t, "true", string(device["current"]))
	var s deviceKeySession
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &s))
	require.NotEmpty(f.t, s.TokenSet.AccessToken)
	require.Equal(f.t, "Bearer", s.TokenSet.TokenType)
	require.NotEmpty(f.t, s.DeviceKey.ID)
	return s
}

func (f *factorFlow) beginDeviceLogin(id string) deviceKeyChallenge {
	f.t.Helper()
	res := f.expect(http.StatusOK, f.post("/device-keys/login/begin", map[string]any{"device_key_id": id}))
	var challenge deviceKeyChallenge
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &challenge))
	return challenge
}

func (f *factorFlow) finishDeviceLogin(challenge deviceKeyChallenge, key ed25519.PrivateKey, domain string) authAnswer {
	f.t.Helper()
	return f.post("/device-keys/login/finish", map[string]any{"challenge_id": challenge.ChallengeID, "signature": f.signDeviceChallenge(key, domain, challenge.Challenge)})
}

func (f *factorFlow) loginDeviceKey(id string, key ed25519.PrivateKey) deviceKeySession {
	f.t.Helper()
	return f.deviceKeySession(f.expect(http.StatusOK, f.finishDeviceLogin(f.beginDeviceLogin(id), key, devicekey.LoginDomain)))
}

// requireActiveDeviceKeys asserts the account's active keys, oldest first.
func (f *factorFlow) requireActiveDeviceKeys(userID string, want ...string) {
	f.t.Helper()
	keys, err := f.auth.DeviceKeys(f.t.Context(), userID)
	require.NoError(f.t, err)
	var got []string
	for _, key := range keys {
		if key.RevokedAt == nil {
			got = append(got, base64.RawURLEncoding.EncodeToString(key.PublicKey))
		}
	}
	require.Equal(f.t, want, got)
}

// deviceKeyNotices lists the addresses told of a device-key enrollment, to
// to ("" = anyone).
func (f *factorFlow) deviceKeyNotices(to string) []string {
	var out []string
	for _, m := range f.outbox.Messages(iam.MessageDeviceKeyEnrolled, to) {
		out = append(out, m.To)
	}
	return out
}

// TestNativeCredentialWorkflow drives the native credentials end to end: a
// passkey's registration, discoverable sign-in, replay and counter checks and
// management, and a device key's enrollment, sign-in, second-factor gate,
// listing, revocation and sign-out.
func TestNativeCredentialWorkflow(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DeviceKeys.Enabled = true
		c.Passkeys = authkit.PasskeyConfig{RPID: "example.com", RPDisplayName: "Example", Origins: []string{"https://example.com"}, UserVerification: "preferred"}
	}))
	t.Run("passkey", func(t *testing.T) { testPasskeyCeremonyAndAssurance(t, auth, outbox) })
	t.Run("device_key", func(t *testing.T) { testDeviceKeyLifecycle(t, auth, outbox) })
}

func testPasskeyCeremonyAndAssurance(t *testing.T, auth *authkit.Client, outbox *authtest.Outbox) {
	// The wire shapes the browser sees, decoded as far as the test reads them.
	type creationOptions struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
			AuthenticatorSelection struct {
				ResidentKey string `json:"residentKey"`
			} `json:"authenticatorSelection"`
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	type requestOptions struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			RPID             string `json:"rpId"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	type passkey = signInKey
	f := newFactorFlow(t, auth, outbox)
	u := authtest.NewUser(t, auth)
	setupToken := authtest.SignIn(t, auth, u).AccessToken
	authn := passkeytest.New(t, "https://example.com")
	decode := func(res authAnswer, v any) {
		t.Helper()
		require.NoError(t, json.Unmarshal([]byte(res.raw), v), res.raw)
	}
	begin := func() requestOptions {
		t.Helper()
		var assertion requestOptions
		decode(f.expect(http.StatusOK, f.post("/passkeys/login/begin", map[string]any{})), &assertion)
		require.Empty(t, assertion.PublicKey.AllowCredentials)
		return assertion
	}
	finish := func(assertion requestOptions, signCount uint32) authAnswer {
		return f.post("/passkeys/login/finish", authn.Assertion(t, assertion.PublicKey.RPID, assertion.PublicKey.Challenge, signCount))
	}
	list := func() []passkey {
		t.Helper()
		return f.signInKeys(setupToken, "passkey")
	}

	var creation creationOptions
	decode(f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/register/begin", setupToken, map[string]any{})), &creation)
	require.Equal(t, "Example", creation.PublicKey.RP.Name)
	require.Equal(t, "example.com", creation.PublicKey.RP.ID)
	require.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.ResidentKey)
	require.Empty(t, creation.PublicKey.ExcludeCredentials)
	attestation := authn.Attestation(t, creation.PublicKey.RP.ID, passkeytest.UserHandle(t, creation.PublicKey.User.ID), creation.PublicKey.Challenge)
	var created passkey
	decode(f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/passkeys/register/finish", setupToken, attestation)), &created)
	require.NotEmpty(t, created.ID)
	require.Equal(t, "passkey", created.Kind)
	require.False(t, created.Current)

	decode(f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/register/begin", setupToken, map[string]any{})), &creation)
	require.Len(t, creation.PublicKey.ExcludeCredentials, 1)
	require.Equal(t, base64.RawURLEncoding.EncodeToString(authn.CredentialID), creation.PublicKey.ExcludeCredentials[0].ID)

	for _, body := range []string{`{"identifier":"does-not-exist@example.com"}`, `{"identifier":"` + u.Email + `"}`, `{"`, `[]`, `null`} {
		f.expect(http.StatusBadRequest, f.post("/passkeys/login/begin", body))
	}
	var assertion requestOptions
	decode(f.expect(http.StatusOK, f.post("/passkeys/login/begin", "")), &assertion)
	require.Empty(t, assertion.PublicKey.AllowCredentials)
	first := authn.Assertion(t, assertion.PublicKey.RPID, assertion.PublicKey.Challenge, 1)
	signedIn := f.post("/passkeys/login/finish", first).signedIn(t)
	require.NotEmpty(t, signedIn.RefreshToken)
	claims := accessClaims(f.t, signedIn.AccessToken)
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
	require.ElementsMatch(t, []any{"swk", "mfa"}, claims["amr"])
	require.NotZero(t, claims["auth_time"])

	// #288/9: the ceremony was consumed by the first finish; the identical
	// assertion replayed is refused.
	f.expect(http.StatusUnauthorized, f.post("/passkeys/login/finish", first))
	f.expect(http.StatusOK, finish(begin(), 2))
	// A signature counter that did not advance is a cloned authenticator.
	stale := f.expect(http.StatusUnauthorized, finish(begin(), 2))
	require.Contains(t, stale.raw, "invalid_credentials")

	listed := list()
	require.Len(t, listed, 1)
	require.NotNil(t, listed[0].LastUsedAt)
	require.Equal(t, created.ID, listed[0].ID)
	// Management uses the credential established by the actual ceremony.
	for _, label := range []string{"old", "new"} {
		var renamed passkey
		decode(f.expect(http.StatusOK, f.request(http.MethodPatch, "/me/sign-in-keys/"+created.ID, setupToken, map[string]any{"label": label})), &renamed)
		require.Equal(t, label, *renamed.Label)
		listed = list()
		require.NotNil(t, listed[0].Label)
		require.Equal(t, label, *listed[0].Label)
	}
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/sign-in-keys/"+created.ID, setupToken, nil))
	require.Empty(t, list())
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/sign-in-keys/"+created.ID, setupToken, nil)) // idempotent
	f.expect(http.StatusNotFound, f.request(http.MethodPatch, "/me/sign-in-keys/"+created.ID, setupToken, map[string]any{"label": "gone"}))
	assertion = requestOptions{}
	decode(f.expect(http.StatusOK, f.post("/passkeys/login/begin", map[string]any{})), &assertion)
	deleted := finish(assertion, 3)
	require.Equal(t, http.StatusUnauthorized, deleted.status, "deleted credentials cannot sign in: %s", deleted.raw)
}

func testDeviceKeyLifecycle(t *testing.T, auth *authkit.Client, outbox *authtest.Outbox) {
	f := newFactorFlow(t, auth, outbox)
	ctx := t.Context()
	const email = "device-key@example.com"
	publicKey, privateKey := f.newDeviceKey()

	enrollment := f.beginDeviceEnrollment(email, publicKey)
	// One typo does not burn the ceremony; the bounded attempt counter does.
	wrongCode := "000000"
	if f.code(iam.MessageVerification, email) == wrongCode {
		wrongCode = "000001"
	}
	f.expect(http.StatusUnauthorized, f.post("/device-keys/enroll/finish", map[string]any{
		"enrollment_id": enrollment.EnrollmentID,
		"code":          wrongCode,
		"signature":     f.signDeviceChallenge(privateKey, devicekey.EnrollmentDomain, enrollment.Challenge),
	}))

	enrolled := f.finishDeviceEnrollment(email, enrollment, privateKey)
	claims := accessClaims(f.t, enrolled.TokenSet.AccessToken)
	require.ElementsMatch(t, []any{"device_key", "email"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelPassword, claims["acr"])
	require.Equal(t, enrolled.DeviceKey.ID, claims["device_key_id"])
	require.NotEmpty(t, claims["auth_time"])
	require.NotEmpty(t, claims["sub"])
	require.NotContains(t, claims, "sid")

	user, err := auth.User(ctx, iam.UserByEmail(email))
	require.NoError(t, err)
	require.True(t, user.EmailVerified)
	f.requireActiveDeviceKeys(user.ID, publicKey)
	var me struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	profile := f.expect(http.StatusOK, f.request(http.MethodGet, "/me", enrolled.TokenSet.AccessToken, nil))
	require.NoError(t, json.Unmarshal([]byte(profile.raw), &me))
	require.Equal(t, user.ID, me.ID)
	require.Empty(t, me.Username)
	sessions, err := auth.Sessions(ctx, user.ID)
	require.NoError(t, err)
	require.Empty(t, sessions, "a device key signs in without a refresh session")

	// Enrollment is single use.
	f.expect(http.StatusUnauthorized, f.post("/device-keys/enroll/finish", map[string]any{
		"enrollment_id": enrollment.EnrollmentID,
		"code":          f.code(iam.MessageVerification, email),
		"signature":     f.signDeviceChallenge(privateKey, devicekey.EnrollmentDomain, enrollment.Challenge),
	}))

	login := f.beginDeviceLogin(enrolled.DeviceKey.ID)
	// Cross-purpose signatures are refused without consuming the valid challenge.
	f.expect(http.StatusUnauthorized, f.finishDeviceLogin(login, privateKey, devicekey.EnrollmentDomain))
	loggedIn := f.deviceKeySession(f.expect(http.StatusOK, f.finishDeviceLogin(login, privateKey, devicekey.LoginDomain)))
	require.Equal(t, enrolled.DeviceKey.ID, loggedIn.DeviceKey.ID)
	require.ElementsMatch(t, []any{"device_key"}, accessClaims(f.t, loggedIn.TokenSet.AccessToken)["amr"])
	require.NotContains(t, accessClaims(f.t, loggedIn.TokenSet.AccessToken), "sid")

	// The login challenge is single use.
	f.expect(http.StatusUnauthorized, f.finishDeviceLogin(login, privateKey, devicekey.LoginDomain))
	require.Empty(t, f.deviceKeyNotices(""), "new accounts have no existing owner to notify")
	known := f.beginDeviceLogin(enrolled.DeviceKey.ID)
	unknown := f.beginDeviceLogin("018f6f74-9f0c-7b27-8000-000000000001")
	require.Len(t, known.ChallengeID, len(unknown.ChallengeID))
	require.Len(t, known.Challenge, len(unknown.Challenge))
	require.False(t, known.ExpiresAt.IsZero())
	require.False(t, unknown.ExpiresAt.IsZero())
	f.expect(http.StatusUnauthorized, f.finishDeviceLogin(unknown, privateKey, devicekey.LoginDomain))

	first, firstPrivate := enrolled, privateKey
	secondPublic, secondPrivate := f.newDeviceKey()
	second := f.finishDeviceEnrollment(email, f.beginDeviceEnrollment(email, secondPublic), secondPrivate)
	require.Equal(t, claims["sub"], accessClaims(f.t, second.TokenSet.AccessToken)["sub"])
	require.NotEqual(t, first.DeviceKey.ID, second.DeviceKey.ID)
	require.Equal(t, []string{email}, f.deviceKeyNotices(""), "an independent machine notifies the existing owner")
	f.requireActiveDeviceKeys(user.ID, publicKey, secondPublic)
	listKeys := func(token string) []httpapi.SignInKey {
		t.Helper()
		var list struct {
			Data []httpapi.SignInKey `json:"data"`
		}
		listed := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/sign-in-keys", token, nil))
		require.NoError(t, json.Unmarshal([]byte(listed.raw), &list))
		for _, key := range list.Data {
			require.Equal(t, httpapi.SignInKeyDeviceKey, key.Kind)
		}
		return list.Data
	}
	keys := listKeys(second.TokenSet.AccessToken)
	require.Len(t, keys, 2)
	current := 0
	for _, key := range keys {
		if key.Current {
			current++
			require.Equal(t, second.DeviceKey.ID, key.ID)
		}
	}
	require.Equal(t, 1, current)

	// An ordinary device-key token is not a recovery-root proof.
	loggedIn = f.loginDeviceKey(second.DeviceKey.ID, secondPrivate)
	f.expect(http.StatusForbidden, f.request(http.MethodDelete, "/device-keys", loggedIn.TokenSet.AccessToken, nil))

	// Re-enrolling the exact active key is an email proof, not a new machine.
	proof := f.finishDeviceEnrollment(email, f.beginDeviceEnrollment(email, secondPublic), secondPrivate)
	require.Equal(t, second.DeviceKey.ID, proof.DeviceKey.ID)
	require.Len(t, listKeys(proof.TokenSet.AccessToken), 2, "no key was added")
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/device-keys", proof.TokenSet.AccessToken, nil))
	f.requireActiveDeviceKeys(user.ID, secondPublic)

	// The replaced machine can no longer mint a token; the kept machine can.
	f.expect(http.StatusUnauthorized, f.finishDeviceLogin(f.beginDeviceLogin(first.DeviceKey.ID), firstPrivate, devicekey.LoginDomain))
	kept := f.loginDeviceKey(second.DeviceKey.ID, secondPrivate)

	// Sign-out (DELETE /logout) revokes the token's own key and is retry-safe:
	// the revoked key's residual token can only confirm its own sign-out,
	// never act on the account.
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/logout", kept.TokenSet.AccessToken, nil))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/logout", kept.TokenSet.AccessToken, nil))
	f.requireActiveDeviceKeys(user.ID)
	f.expect(http.StatusUnauthorized, f.request(http.MethodDelete, "/me/sign-in-keys/"+first.DeviceKey.ID, kept.TokenSet.AccessToken, nil))
	f.expect(http.StatusUnauthorized, f.request(http.MethodDelete, "/device-keys", kept.TokenSet.AccessToken, nil))

	// Tombstoned key bytes cannot be reactivated through email recovery.
	reenroll := f.beginDeviceEnrollment(email, secondPublic)
	f.expect(http.StatusUnauthorized, f.post("/device-keys/enroll/finish", map[string]any{
		"enrollment_id": reenroll.EnrollmentID,
		"code":          f.code(iam.MessageVerification, email),
		"signature":     f.signDeviceChallenge(secondPrivate, devicekey.EnrollmentDomain, reenroll.Challenge),
	}))

	// #293: an account with a second factor presents it before a device key,
	// a standing credential, is enrolled on it. The emailed code alone is
	// refused naming the factor and the parameter, and a wrong factor leaves
	// the ceremony live.
	holder := authtest.NewUser(t, auth)
	holder.TOTP = authtest.EnrollTOTP(t, auth, holder)
	holderPublic, holderPrivate := f.newDeviceKey()
	gated := f.beginDeviceEnrollment(holder.Email, holderPublic)
	gatedFinish := func(secondFactor string) authAnswer {
		body := map[string]any{
			"enrollment_id": gated.EnrollmentID,
			"code":          f.code(iam.MessageVerification, holder.Email),
			"signature":     f.signDeviceChallenge(holderPrivate, devicekey.EnrollmentDomain, gated.Challenge),
		}
		if secondFactor != "" {
			body["code_2fa"] = secondFactor
		}
		return f.post("/device-keys/enroll/finish", body)
	}
	refused := f.expect(http.StatusForbidden, gatedFinish(""))
	require.Equal(t, "2fa_required", refused.Error.Code)
	require.Equal(t, "code_2fa", refused.Error.Param)
	require.Equal(t, "totp", refused.Error.Metadata.Method)
	f.expect(http.StatusUnauthorized, gatedFinish("000000"))
	withFactor := f.deviceKeySession(f.expect(http.StatusOK, gatedFinish(holder.TOTP.Code(t))))
	claims = accessClaims(f.t, withFactor.TokenSet.AccessToken)
	require.ElementsMatch(t, []any{"device_key", "email", "otp", "mfa"}, claims["amr"])
	require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
	require.Equal(t, holder.ID, claims["sub"])
	f.requireActiveDeviceKeys(holder.ID, holderPublic)
	require.Equal(t, []string{holder.Email}, f.deviceKeyNotices(holder.Email))
}
