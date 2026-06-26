package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestLogInternalErrorInvokesHook(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	req := httptest.NewRequest("POST", "/register", nil)

	called := false
	svc := &Service{errorLogger: func(ctx context.Context, event InternalErrorEvent) {
		called = true
		if ctx != req.Context() {
			t.Fatalf("expected request context")
		}
		if event.Route != "register" {
			t.Fatalf("route=%q, want register", event.Route)
		}
		if event.Stage != "validate_username" {
			t.Fatalf("stage=%q, want validate_username", event.Stage)
		}
		if event.Code != "database_error" {
			t.Fatalf("code=%q, want database_error", event.Code)
		}
		if event.Method != "POST" {
			t.Fatalf("method=%q, want POST", event.Method)
		}
		if event.Path != "/register" {
			t.Fatalf("path=%q, want /register", event.Path)
		}
		if !errors.Is(event.Err, wantErr) {
			t.Fatalf("err=%v, want %v", event.Err, wantErr)
		}
	}}

	svc.logInternalError(req, "register", "validate_username", "database_error", wantErr)
	if !called {
		t.Fatal("expected error hook to be called")
	}
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
