package authhttp

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

type testEmailSender struct{}

func (testEmailSender) SendVerification(context.Context, string, string, core.VerificationMessage) error {
	return nil
}
func (testEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	return nil
}
func (testEmailSender) SendLoginCode(context.Context, string, string, string) error {
	return nil
}
func (testEmailSender) SendWelcome(context.Context, string, string) error {
	return nil
}

type failingVerificationEmailSender struct {
	testEmailSender
}

func (failingVerificationEmailSender) SendVerification(context.Context, string, string, core.VerificationMessage) error {
	return errors.New("provider rejected message")
}

func newRegistrationTestService(t *testing.T, policy core.RegistrationVerificationPolicy) *Service {
	t.Helper()

	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]*rsa.PublicKey{"test-kid": signer.PublicKey()}}
	coreSvc := core.NewService(core.Options{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		AccessTokenDuration:      time.Hour,
		RegistrationVerification: policy,
		Environment:              "test",
	}, ks).WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory)

	ver := NewVerifier(WithSkew(5 * time.Second))
	_ = ver.AddIssuer(coreSvc.Options().Issuer, coreSvc.Options().ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)

	return &Service{svc: coreSvc, verifier: ver}
}

func TestRegistrationResponseBuilder(t *testing.T) {
	email := "user@example.com"
	phone := "+15551234567"

	require.Equal(t, registrationResponse{
		OK:              true,
		Username:        "user",
		Email:           &email,
		PhoneNumber:     nil,
		DiscordUsername: nil,
		NextAction:      registrationNextActionVerifyEmail,
	}, newRegistrationResponse("user", &email, nil, registrationNextActionVerifyEmail, nil))

	require.Equal(t, registrationResponse{
		OK:              true,
		Username:        "user",
		Email:           nil,
		PhoneNumber:     &phone,
		DiscordUsername: nil,
		NextAction:      registrationNextActionVerifyPhone,
	}, newRegistrationResponse("user", nil, &phone, registrationNextActionVerifyPhone, nil))

	require.Equal(t, registrationResponse{
		OK:              true,
		Username:        "user",
		Email:           &email,
		PhoneNumber:     nil,
		DiscordUsername: nil,
		NextAction:      registrationNextActionNone,
	}, newRegistrationResponse("user", &email, nil, registrationNextActionNone, nil))

	require.Equal(t, registrationResponse{
		OK:              true,
		Username:        "user",
		Email:           &email,
		PhoneNumber:     nil,
		DiscordUsername: nil,
		NextAction:      registrationNextActionNone,
		AccessToken:     "access",
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		RefreshToken:    "refresh",
	}, newRegistrationResponse("user", &email, nil, registrationNextActionNone, &authTokensResponse{
		AccessToken:  "access",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh",
	}))
}

func TestAPIHandler_RegisterRequiredEmailVerificationResponse(t *testing.T) {
	s := newRegistrationTestService(t, core.RegistrationVerificationRequired).
		WithEmailSender(testEmailSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{
		"identifier":"user@example.com",
		"username":"user",
		"password":"password123"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, true, body["ok"])
	require.Equal(t, "user", body["username"])
	require.Equal(t, "user@example.com", body["email"])
	require.Nil(t, body["phone_number"])
	require.Nil(t, body["discord_username"])
	require.Equal(t, string(registrationNextActionVerifyEmail), body["next_action"])
	require.NotContains(t, body, "message")
}

func TestAPIHandler_RegisterEmailDeliveryFailure(t *testing.T) {
	s := newRegistrationTestService(t, core.RegistrationVerificationRequired).
		WithEmailSender(failingVerificationEmailSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{
		"identifier":"user@example.com",
		"username":"user",
		"password":"password123"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"email_delivery_failed"}`, w.Body.String())
}

func TestAPIHandler_RegisterResendEmailDeliveryFailure(t *testing.T) {
	s := newRegistrationTestService(t, core.RegistrationVerificationRequired)
	_, err := s.svc.CreatePendingRegistration(context.Background(), "user@example.com", "user", "argon2id$hash", 0)
	require.NoError(t, err)
	s = s.WithEmailSender(failingVerificationEmailSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{
		"email":"user@example.com"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"email_delivery_failed"}`, w.Body.String())
}

func TestAPIHandler_RegisterResendEmailHasPrivatePeerCooldown(t *testing.T) {
	s, err := NewService(core.Config{
		Issuer:                   "https://example.com",
		IssuedAudiences:          []string{"test-app"},
		ExpectedAudiences:        []string{"test-app"},
		BaseURL:                  "https://example.com",
		RegistrationVerification: core.RegistrationVerificationRequired,
	})
	require.NoError(t, err)
	s = s.WithEmailSender(testEmailSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{"email":"user@example.com"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "172.21.0.1:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"pending_registration_not_found"}`, w.Body.String())

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{"email":"user@example.com"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "172.21.0.1:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	require.Equal(t, "60", w.Header().Get("Retry-After"))
	require.Contains(t, w.Body.String(), `"error":"rate_limited"`)
	require.Contains(t, w.Body.String(), `"retry_after_seconds":60`)
}
