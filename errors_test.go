package authkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/documents"
)

// One error model (ak#290): identity is the code, the status is the
// catalog's, wrapping keeps both, and every catalogued code has a message.
func TestErrorModel(t *testing.T) {
	if !errors.Is(fmt.Errorf("wrap: %w", ErrUserBanned), ErrUserBanned) {
		t.Fatal("a wrapped sentinel must keep errors.Is identity")
	}
	if !errors.Is(E(CodeUserBanned, WithCause(errors.New("row"))), ErrUserBanned) {
		t.Fatal("a fresh E(code) is the same identity as the sentinel")
	}
	if errors.Is(ErrUserBanned, ErrUserNotFound) {
		t.Fatal("different codes are different identities")
	}
	if ErrUserBanned.Error() != "user_banned" || ErrUserBanned.Status != http.StatusUnauthorized {
		t.Fatalf("sentinel = %q/%d", ErrUserBanned.Error(), ErrUserBanned.Status)
	}
	if e := AsError(fmt.Errorf("x: %w", ErrGroupNotFound)); e == nil || e.Code != CodeGroupNotFound || e.Code != "permission_group_not_found" {
		t.Fatalf("AsError through a wrap = %+v", e)
	}
	if AsError(errors.New("opaque")) != nil {
		t.Fatal("a plain error is not an *Error")
	}
	re := Recode(E(CodeInvalidEmail, WithMeta("k", 1)), CodeInvalidRequest, WithStatus(http.StatusBadRequest))
	if re.Code != CodeInvalidRequest || re.Param != "email" || re.Meta["k"] != 1 || !errors.Is(re, ErrInvalidRequest) {
		t.Fatalf("Recode lost fields: %+v", re)
	}
	if e := E(CodeInvalidEmail); e.Param != "" || e.Status != http.StatusBadRequest {
		t.Fatalf("catalog status/param for a validation code = %d/%q", e.Status, e.Param)
	}
	if _, _, ok := DescribeCode("no_such_code"); ok {
		t.Fatal("unknown codes are not catalogued")
	}
	if e := E("no_such_code"); e.Status != http.StatusInternalServerError {
		t.Fatal("an uncatalogued code is a 500")
	}
	for _, c := range Codes() {
		status, message, ok := DescribeCode(c)
		if !ok || status < 400 || status > 599 || message == "" {
			t.Errorf("catalog entry %q = %d/%q", c, status, message)
		}
	}
	if !errors.Is(documents.ErrNotFound, documents.ErrNotFound) || documents.ErrNotFound.Status != http.StatusNotFound {
		t.Fatal("documents codes live on the same model")
	}
}

// The wire envelope: type from status, message from the catalog, param and
// metadata only when present, and every 500 — or any non-Error — as
// internal_error.
func TestErrorEnvelope(t *testing.T) {
	status, env := ErrorEnvelopeFor(ErrInvalidAccessToken)
	b, _ := json.Marshal(env)
	if want := `{"error":{"type":"authentication_error","code":"invalid_token","message":"The authentication token is invalid."}}`; status != 401 || string(b) != want {
		t.Fatalf("envelope = %d %s", status, b)
	}
	status, env = ErrorEnvelopeFor(E(CodeInvalidEmail, WithMeta("retry_after_seconds", 5)))
	if status != 400 || env.Error.Param == nil || *env.Error.Param != "email" || env.Error.Metadata["retry_after_seconds"] != 5 || env.Error.Type != ErrorTypeInvalidRequest {
		t.Fatalf("validation envelope = %d %+v", status, env)
	}
	for _, err := range []error{errors.New("opaque"), nil, E(CodeTokenIssueFailed), fmt.Errorf("%w: cause", ErrSessionIssueFailed)} {
		status, env := ErrorEnvelopeFor(err)
		if status != 500 || env.Error.Code != "internal_error" || env.Error.Type != ErrorTypeAPI {
			t.Errorf("%v -> %d %s", err, status, env.Error.Code)
		}
	}
	if status, env := ErrorEnvelopeFor(fmt.Errorf("%w: smtp", ErrEmailDeliveryFailed)); status != 502 || env.Error.Code != "email_delivery_failed" {
		t.Fatalf("a 502 keeps its code: %d %s", status, env.Error.Code)
	}
	for st, want := range map[int]string{400: ErrorTypeInvalidRequest, 404: ErrorTypeInvalidRequest, 409: ErrorTypeInvalidRequest, 401: ErrorTypeAuthentication, 403: ErrorTypeAuthorization, 429: ErrorTypeRateLimit, 500: ErrorTypeAPI, 503: ErrorTypeAPI} {
		if got := ErrorTypeForStatus(st); got != want {
			t.Errorf("ErrorTypeForStatus(%d) = %q, want %q", st, got, want)
		}
	}
}
