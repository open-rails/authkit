package authhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

func TestLogInternalErrorInvokesHook(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	req := httptest.NewRequest("POST", "/register", nil)

	called := false
	svc := (&Service{}).WithErrorLogger(func(ctx context.Context, event InternalErrorEvent) {
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
	})

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
		body   string
	}{
		{name: "invalid_email", err: core.ValidateEmail("bad"), status: http.StatusBadRequest, body: `{"error":"invalid_email"}`},
		{name: "user_not_found", err: core.ErrUserNotFound, status: http.StatusNotFound, body: `{"error":"user_not_found"}`},
		{name: "pending_registration_not_found", err: core.ErrPendingRegistrationNotFound, status: http.StatusNotFound, body: `{"error":"pending_registration_not_found"}`},
		{name: "email_already_verified", err: core.ErrEmailAlreadyVerified, status: http.StatusConflict, body: `{"error":"email_already_verified"}`},
		{name: "phone_already_verified", err: core.ErrPhoneAlreadyVerified, status: http.StatusConflict, body: `{"error":"phone_already_verified"}`},
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
			require.JSONEq(t, tt.body, w.Body.String())
		})
	}
}
