package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

type testSMSSender struct{}

func (testSMSSender) SendVerification(context.Context, string, core.VerificationMessage) error {
	return nil
}
func (testSMSSender) SendPasswordResetLink(context.Context, string, string) error {
	return nil
}
func (testSMSSender) SendLoginCode(context.Context, string, string) error {
	return nil
}

func TestEmailVerifyRequestRejectsMalformedInput(t *testing.T) {
	s := newTestService(t).WithEmailSender(testEmailSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"invalid_email"}`, w.Body.String())
}

func TestPhoneVerifyRequestRejectsMalformedInput(t *testing.T) {
	s := newTestService(t).WithSMSSender(testSMSSender{})
	h := s.APIHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/phone/verify/request", strings.NewReader(`{"phone_number":"not-phone"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"invalid_phone_number"}`, w.Body.String())
}
