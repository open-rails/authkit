package authbase

import (
	"encoding/json"
	"testing"
)

func TestErrorTypeForStatus(t *testing.T) {
	cases := map[int]string{
		400: ErrorTypeInvalidRequest,
		404: ErrorTypeInvalidRequest,
		409: ErrorTypeInvalidRequest,
		401: ErrorTypeAuthentication,
		403: ErrorTypeAuthorization,
		429: ErrorTypeRateLimit,
		500: ErrorTypeAPI,
		503: ErrorTypeAPI,
	}
	for status, want := range cases {
		if got := ErrorTypeForStatus(status); got != want {
			t.Errorf("ErrorTypeForStatus(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestErrorMessageCuratedAndFallback(t *testing.T) {
	if got := ErrorMessage("rate_limited"); got != "Too many requests. Please try again later." {
		t.Errorf("curated message = %q", got)
	}
	// Humanized fallback for an uncurated code, with acronym uppercasing.
	if got := ErrorMessage("2fa_send_failed"); got != "2FA send failed." {
		t.Errorf("humanized = %q, want %q", got, "2FA send failed.")
	}
	if got := ErrorMessage("access_token_not_found"); got != "Access token not found." {
		t.Errorf("humanized = %q, want %q", got, "Access token not found.")
	}
	if ErrorMessage("anything_at_all") == "" {
		t.Error("message must never be empty")
	}
}

func TestNewErrorEnvelopeShape(t *testing.T) {
	env := NewErrorEnvelope(401, "invalid_token", nil, nil)
	if env.Error.Type != ErrorTypeAuthentication {
		t.Errorf("type = %q", env.Error.Type)
	}
	if env.Error.Code != "invalid_token" || env.Error.Message == "" {
		t.Errorf("code/message = %q / %q", env.Error.Code, env.Error.Message)
	}
	// param + empty metadata are omitted from the wire JSON.
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	want := `{"error":{"type":"authentication_error","code":"invalid_token","message":"The authentication token is invalid."}}`
	if got != want {
		t.Errorf("envelope JSON =\n  %s\nwant\n  %s", got, want)
	}

	// param + metadata appear when set.
	p := "email"
	env2 := NewErrorEnvelope(400, "invalid_email", &p, map[string]any{"retry_after_seconds": 5})
	b2, _ := json.Marshal(env2)
	var round ErrorEnvelope
	if err := json.Unmarshal(b2, &round); err != nil {
		t.Fatal(err)
	}
	if round.Error.Param == nil || *round.Error.Param != "email" {
		t.Errorf("param not round-tripped: %+v", round.Error.Param)
	}
	if round.Error.Metadata["retry_after_seconds"] == nil {
		t.Errorf("metadata not round-tripped: %+v", round.Error.Metadata)
	}
}
