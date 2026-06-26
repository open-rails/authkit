package authhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestLogInternalErrorLogsToSlog(t *testing.T) {
	// Not parallel: swaps the process-global slog default.
	wantErr := errors.New("boom")
	req := httptest.NewRequest("POST", "/register", nil)

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	svc := &Service{}
	svc.logInternalError(req, "register", "validate_username", "database_error", wantErr)

	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	require.Equal(t, "register", rec["route"])
	require.Equal(t, "validate_username", rec["stage"])
	require.Equal(t, "database_error", rec["code"])
	require.Equal(t, "POST", rec["method"])
	require.Equal(t, "/register", rec["path"])
	require.Equal(t, "boom", rec["error"])

	// A nil error must not emit a log record.
	buf.Reset()
	svc.logInternalError(req, "register", "validate_username", "database_error", nil)
	require.Empty(t, buf.String())
}

func TestHandleVerificationRequestErrorMapsHonestTargetErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid_email", err: embedded.ValidateEmail("bad"), status: http.StatusBadRequest, code: "invalid_email"},
		{name: "user_not_found", err: authkit.ErrUserNotFound, status: http.StatusNotFound, code: "user_not_found"},
		{name: "pending_registration_not_found", err: authkit.ErrPendingRegistrationNotFound, status: http.StatusNotFound, code: "pending_registration_not_found"},
		{name: "email_already_verified", err: authkit.ErrEmailAlreadyVerified, status: http.StatusConflict, code: "email_already_verified"},
		{name: "phone_already_verified", err: authkit.ErrPhoneAlreadyVerified, status: http.StatusConflict, code: "phone_already_verified"},
		{name: "verification_link_expired", err: authkit.ErrVerificationLinkExpired, status: http.StatusGone, code: "verification_link_expired"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if !handleVerificationRequestError(w, tt.err) {
				t.Fatal("expected error to be handled")
			}
			if w.Code != tt.status {
				t.Fatalf("status=%d, want %d; body=%s", w.Code, tt.status, w.Body.String())
			}
			// Stripe-style nested envelope (#115): assert code, plus that type +
			// message are always populated.
			var env authkit.ErrorEnvelope
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
			require.Equal(t, tt.code, env.Error.Code)
			require.NotEmpty(t, env.Error.Type)
			require.NotEmpty(t, env.Error.Message)
		})
	}
}
