package authhttp

import (
	"bytes"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// newTestServiceWithPolicy builds an http.Service whose core Options carry the
// registration modes under test. OrgMode is "multi" so the org-management
// routes exist and can be exercised.
func newTestServiceWithPolicy(t *testing.T, nativeMode, orgMode core.RegistrationMode) *Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := core.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	opts := core.Options{
		Issuer:              "https://example.com",
		IssuedAudiences:     []string{"test-app"},
		ExpectedAudiences:   []string{"test-app"},
		AccessTokenDuration: time.Hour,
		// These tests don't exercise registration verification delivery; opt out
		// so APIHandler's ValidateVerificationConfiguration doesn't panic on the
		// default "required" policy with no sender configured.
		RegistrationVerification:   core.RegistrationVerificationNone,
		NativeUserRegistrationMode: nativeMode,
		OrgRegistrationMode:        orgMode,
	}
	coreSvc := core.NewService(opts, ks)
	ver := NewVerifier(WithSkew(5*time.Second), WithOrgMode("multi"))
	_ = ver.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{
		RawKeys: coreSvc.PublicKeysByKID(),
	})
	ver.WithService(coreSvc)
	return &Service{svc: coreSvc, verifier: ver}
}

func bodyError(t *testing.T, raw []byte) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &resp))
	return resp.Error
}

// --- Default config preserves current behavior ---

func TestPolicyDefaults_PreserveCurrentBehavior(t *testing.T) {
	opts := newTestService(t).svc.Options()
	require.Equal(t, core.RegistrationModeOpen, opts.NativeUserRegistrationMode)
	require.Equal(t, core.RegistrationModeOpen, opts.OrgRegistrationMode)
	require.True(t, opts.PublicNativeUserRegistrationEnabled())
	require.True(t, opts.PublicOrgRegistrationEnabled())
}

func TestPolicyDefaults_RegisterNotShortCircuited(t *testing.T) {
	// With defaults, /register must NOT return registration_disabled. It will
	// fail later (no Postgres) but the policy gate must not fire.
	s := newTestService(t)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register",
		bytes.NewReader([]byte(`{"identifier":"a@b.com","username":"alice","password":"Sup3rSecret!"}`)))
	h.ServeHTTP(w, r)
	require.NotEqual(t, errRegistrationDisabled, bodyError(t, w.Body.Bytes()))
}

// --- Registration disabled: every audited public path is rejected ---

func TestRegistrationDisabled_RegisterPOST(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register",
		bytes.NewReader([]byte(`{"identifier":"a@b.com","username":"alice","password":"Sup3rSecret!"}`)))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, errRegistrationDisabled, bodyError(t, w.Body.Bytes()))
}

func TestRegistrationDisabled_AvailabilityNeverUsable(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/register/availability?username=alice&email=a@b.com", nil)
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var resp registrationAvailabilityResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Username)
	require.False(t, resp.Username.Available, "username must never be reported usable")
	require.Equal(t, errRegistrationDisabled, resp.Username.Error)
	require.NotNil(t, resp.Email)
	require.False(t, resp.Email.Available, "email must never be reported usable")
	require.Equal(t, errRegistrationDisabled, resp.Email.Error)
}

func TestRegistrationDisabled_ResendEmail(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-email",
		bytes.NewReader([]byte(`{"email":"a@b.com"}`)))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, errRegistrationDisabled, bodyError(t, w.Body.Bytes()))
}

func TestRegistrationDisabled_ResendPhone(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/register/resend-phone",
		bytes.NewReader([]byte(`{"phone_number":"+12025550123"}`)))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, errRegistrationDisabled, bodyError(t, w.Body.Bytes()))
}

// Core-level gates (cover non-HTTP callers and defense-in-depth on the
// pending-registration + confirmation + Solana auto-create chokepoints).
func TestRegistrationDisabled_CorePendingAndConfirmGates(t *testing.T) {
	coreSvc := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen).svc

	_, err := coreSvc.CreatePendingRegistration(t.Context(), "a@b.com", "alice", "hash", 0)
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)

	_, err = coreSvc.CreatePendingPhoneRegistration(t.Context(), "+12025550123", "alice", "hash")
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)

	_, err = coreSvc.ConfirmPendingRegistration(t.Context(), "any-token")
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)

	_, err = coreSvc.ConfirmPendingPhoneRegistration(t.Context(), "+12025550123", "123456")
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)

	_, err = coreSvc.ConfirmPendingPhoneRegistrationByToken(t.Context(), "any-token")
	require.ErrorIs(t, err, core.ErrRegistrationDisabled)
}

// When registration is enabled, the core pending-registration gate does NOT
// fire (it proceeds far enough to hit the missing-Postgres error instead).
func TestRegistrationEnabled_CorePendingNotGated(t *testing.T) {
	coreSvc := newTestServiceWithPolicy(t, core.RegistrationModeOpen, core.RegistrationModeOpen).svc
	_, err := coreSvc.CreatePendingRegistration(t.Context(), "a@b.com", "alice", "hash", 0)
	require.Error(t, err)
	require.NotErrorIs(t, err, core.ErrRegistrationDisabled)
}

// --- Existing-user authentication stays available while registration is off ---

// The public auth/login/reset/session routes must remain MOUNTED (not omitted
// or short-circuited by the registration switch). They will fail later for
// other reasons (no Postgres / bad creds), but never with registration_disabled
// and never 404.
func TestRegistrationDisabled_ExistingUserAuthRoutesStillMounted(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	h := s.APIHandler()

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/token", `{}`},
		{http.MethodPost, "/password/login", `{"email":"a@b.com","password":"x"}`},
		{http.MethodPost, "/email/password/reset/request", `{"email":"a@b.com"}`},
		{http.MethodPost, "/email/password/reset/confirm", `{"token":"x","password":"y"}`},
		{http.MethodPost, "/phone/password/reset/request", `{"phone_number":"+12025550123"}`},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(tc.body)))
		h.ServeHTTP(w, r)
		require.NotEqual(t, http.StatusNotFound, w.Code, "%s %s should be mounted", tc.method, tc.path)
		require.NotEqual(t, errRegistrationDisabled, bodyError(t, w.Body.Bytes()),
			"%s %s must not be gated by registration switch", tc.method, tc.path)
	}
}

// --- Org management disabled ---

func TestOrgManagementDisabled_CreateDenied(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeOpen, core.RegistrationModeManifestOnly)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/orgs", bytes.NewReader([]byte(`{"slug":"acme"}`)))
	h.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, errOrgManagementDisabled, bodyError(t, w.Body.Bytes()))
}

func TestOrgManagementDisabled_MutatingRoutesDenied(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeOpen, core.RegistrationModeManifestOnly)
	h := s.APIHandler()

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/orgs"},
		{http.MethodPost, "/orgs/acme/rename"},
		{http.MethodPost, "/orgs/acme/members"},
		{http.MethodPost, "/orgs/acme/invites"},
		{http.MethodPost, "/orgs/acme/service-tokens"},
		{http.MethodPost, "/me/invites/abc/accept"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(`{}`)))
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusForbidden, w.Code, "%s %s", tc.method, tc.path)
		require.Equal(t, errOrgManagementDisabled, bodyError(t, w.Body.Bytes()), "%s %s", tc.method, tc.path)
	}
}

// Read-only org routes and the org-scoped token route stay available (they
// require auth, so they reject with 401, NOT org_management_disabled).
func TestOrgManagementDisabled_ReadRoutesStillAvailable(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeOpen, core.RegistrationModeManifestOnly)
	h := s.APIHandler()

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/orgs"},
		{http.MethodGet, "/orgs/acme/members"},
		{http.MethodPost, "/token/org"},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte(`{}`)))
		h.ServeHTTP(w, r)
		require.NotEqual(t, http.StatusNotFound, w.Code, "%s %s should be mounted", tc.method, tc.path)
		require.NotEqual(t, errOrgManagementDisabled, bodyError(t, w.Body.Bytes()),
			"%s %s must stay available", tc.method, tc.path)
	}
}

// When org management is enabled (default), the create route is NOT gated.
func TestOrgManagementEnabled_CreateNotGated(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeOpen, core.RegistrationModeOpen)
	h := s.APIHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/orgs", bytes.NewReader([]byte(`{"slug":"acme"}`)))
	h.ServeHTTP(w, r)
	require.NotEqual(t, errOrgManagementDisabled, bodyError(t, w.Body.Bytes()))
}

// --- Selective route-group mounting ---

func TestSelectiveMounting_OmitRegisterGroup(t *testing.T) {
	s := newTestServiceWithPolicy(t, core.RegistrationModeAdminBootstrapOnly, core.RegistrationModeOpen)
	// A locked-down host mounts only Core + Password (no register group at all).
	routes := s.Routes().Groups(RouteCore, RoutePassword)
	requireNoRoute(t, routes, http.MethodPost, "/register")
	requireNoRoute(t, routes, http.MethodGet, "/register/availability")
	requireRoute(t, routes, http.MethodPost, "/token")
	requireRoute(t, routes, http.MethodPost, "/password/login")
	requireNoRoute(t, routes, http.MethodPost, "/orgs")
}
