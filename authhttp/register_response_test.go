package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/jwtkit"
	authlang "github.com/open-rails/authkit/lang"
	"github.com/stretchr/testify/require"
)

type testEmailSender struct{}

func (testEmailSender) SendVerification(context.Context, string, string, embedded.VerificationMessage) error {
	return nil
}
func (testEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	return nil
}
func (testEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
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

func (failingVerificationEmailSender) SendVerification(context.Context, string, string, embedded.VerificationMessage) error {
	return errors.New("provider rejected message")
}

// failableEmailSender delivers successfully until fail is flipped, then rejects
// verification sends. It lets one service exercise the create path (delivery OK)
// and then the resend path (delivery fails); #108 removed the chainable
// WithEmailSender swap this case previously relied on.
type failableEmailSender struct {
	testEmailSender
	fail bool
}

func (s *failableEmailSender) SendVerification(context.Context, string, string, embedded.VerificationMessage) error {
	if s.fail {
		return errors.New("provider rejected message")
	}
	return nil
}

type recordingEmailSender struct {
	testEmailSender
	languages []string
}

func (s *recordingEmailSender) SendVerification(ctx context.Context, email, username string, msg embedded.VerificationMessage) error {
	lang, _ := authlang.LanguageFromContext(ctx)
	s.languages = append(s.languages, lang)
	return nil
}

func newRegistrationTestService(t *testing.T, policy embedded.RegistrationVerificationPolicy, coreOpts ...embedded.Option) *Service {
	t.Helper()

	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := authcore.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := append([]embedded.Option{authcore.WithEphemeralStore(memorystore.NewKV())}, coreOpts...)
	coreSvc := authcore.NewService(embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}, Registration: embedded.RegistrationConfig{Verification: policy}, Environment: "test"}, ks, opts...)

	ver := verify.NewVerifier(verify.WithSkew(5 * time.Second))
	_ = ver.AddIssuer(coreSvc.Config().Token.Issuer, coreSvc.Config().Token.ExpectedAudiences, verify.IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)

	return &Service{svc: coreSvc, verifier: ver}
}

func TestAPIHandler_RegisterRequiredEmailVerificationResponse(t *testing.T) {
	s := newRegistrationTestService(t, embedded.RegistrationVerificationRequired, embedded.WithEmailSender(testEmailSender{}))
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
	s := newRegistrationTestService(t, embedded.RegistrationVerificationRequired, embedded.WithEmailSender(failingVerificationEmailSender{}))
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
	requireErrorCode(t, w.Body.String(), "email_delivery_failed")
}

func TestAPIHandler_RegisterResendEmailDeliveryFailure(t *testing.T) {
	// One service: the initial CreatePendingRegistration delivers fine, then the
	// sender is flipped to fail so the resend path returns email_delivery_failed.
	// (#108 removed the chainable WithEmailSender swap this previously used.)
	sender := &failableEmailSender{}
	s := newRegistrationTestService(t, embedded.RegistrationVerificationRequired, embedded.WithEmailSender(sender))
	_, err := s.svc.CreatePendingRegistrationWithLanguage(context.Background(), "user@example.com", "user", "argon2id$hash", 0, "")
	require.NoError(t, err)
	sender.fail = true
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{
		"email":"user@example.com"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), "email_delivery_failed")
}

func TestAPIHandler_EmailVerifyRequestResendsPendingRegistration(t *testing.T) {
	s := newRegistrationTestService(t, embedded.RegistrationVerificationRequired, embedded.WithEmailSender(testEmailSender{}))
	_, err := s.svc.CreatePendingRegistrationWithLanguage(context.Background(), "user@example.com", "user", "argon2id$hash", 0, "")
	require.NoError(t, err)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{
		"email":"user@example.com"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.JSONEq(t, `{"ok":true}`, w.Body.String())
}

func TestAPIHandler_RegisterSeedsPreferredLanguageAndResendPreservesIt(t *testing.T) {
	sender := &recordingEmailSender{}
	s := newRegistrationTestService(t, embedded.RegistrationVerificationRequired, embedded.WithEmailSender(sender))
	// WithLanguageConfig is an HTTP-level field (#108 removed the chainable
	// setter); the test is package authhttp, so set it directly.
	langCfg := LanguageConfig{Supported: []string{"en", "es"}, Default: "en"}
	s.langCfg = &langCfg
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register?lang=es", strings.NewReader(`{
		"identifier":"user@example.com",
		"username":"user",
		"password":"password123"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Equal(t, []string{"es"}, sender.languages)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/register/resend-email?lang=en", strings.NewReader(`{
		"email":"user@example.com"
	}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Equal(t, []string{"es", "es"}, sender.languages)
}

func TestAPIHandler_RegisterResendEmailHasPrivatePeerCooldown(t *testing.T) {
	s, err := NewServer(newServerClient(t, embedded.Config{
		Keys: embedded.KeysConfig{AllowEphemeralDevKeys: true}, // #231: tests opt in explicitly
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test-app"},
			ExpectedAudiences: []string{"test-app"},
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://example.com"},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationRequired},
	}, newNoDBPool(t), embedded.WithEmailSender(testEmailSender{})))
	require.NoError(t, err)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{"email":"user@example.com"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "172.21.0.1:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	requireErrorCode(t, w.Body.String(), "pending_registration_not_found")

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/register/resend-email", strings.NewReader(`{"email":"user@example.com"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "172.21.0.1:1234"
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	require.Equal(t, "60", w.Header().Get("Retry-After"))
	require.Equal(t, "6", w.Header().Get("RateLimit-Limit"))
	require.Equal(t, "5", w.Header().Get("RateLimit-Remaining"))
	require.Equal(t, "60", w.Header().Get("RateLimit-Reset"))
	require.Contains(t, w.Body.String(), `"code":"rate_limited"`)
	require.Contains(t, w.Body.String(), `"action":"request_email_verification"`)
	require.Contains(t, w.Body.String(), `"allowed":false`)
	require.Contains(t, w.Body.String(), `"reason":"cooldown"`)
	require.Contains(t, w.Body.String(), `"retry_after_seconds":60`)
	require.Contains(t, w.Body.String(), `"next_allowed_at"`)
	require.Contains(t, w.Body.String(), `"limit":6`)
	require.Contains(t, w.Body.String(), `"remaining":5`)
	require.Contains(t, w.Body.String(), `"window_seconds":3600`)
	require.Contains(t, w.Body.String(), `"cooldown_seconds":60`)
}
