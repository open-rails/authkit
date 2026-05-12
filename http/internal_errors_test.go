package authhttp

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
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
