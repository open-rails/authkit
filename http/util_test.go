package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type decodeTarget struct {
	Name string `json:"name"`
}

// decodeJSON must reject bodies larger than maxJSONBodyBytes so no auth endpoint
// can be forced to read an unbounded request body (memory-exhaustion DoS).
func TestDecodeJSONRejectsOversizedBody(t *testing.T) {
	huge := `{"name":"` + strings.Repeat("a", int(maxJSONBodyBytes)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(huge))

	var dst decodeTarget
	err := decodeJSON(req, &dst)
	if err == nil {
		t.Fatal("expected oversized body to be rejected")
	}
	if err.Error() != "body_too_large" {
		t.Fatalf("expected body_too_large, got %q", err.Error())
	}
}

func TestDecodeJSONAcceptsWithinLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"alice"}`))

	var dst decodeTarget
	if err := decodeJSON(req, &dst); err != nil {
		t.Fatalf("expected body within limit to decode, got %v", err)
	}
	if dst.Name != "alice" {
		t.Fatalf("expected name=alice, got %q", dst.Name)
	}
}

func TestDecodeJSONRejectsTrailingGarbage(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"a"}{}`))

	var dst decodeTarget
	if err := decodeJSON(req, &dst); err == nil || err.Error() != "invalid_json" {
		t.Fatalf("expected invalid_json, got %v", err)
	}
}
