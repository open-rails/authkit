package handlers

import (
	"strings"
	"testing"
)

func TestBuildOIDCPopupHTML_UsesSafeTargetOrigin(t *testing.T) {
	payload := []byte(`{"access_token":"abc"}`)

	origin := `https://example.com";alert(1);//`
	html := string(buildOIDCPopupHTML(payload, origin))

	if strings.Contains(html, "postMessage(data, '") {
		t.Fatalf("expected not to embed origin in single-quoted JS string")
	}
	if !strings.Contains(html, "var targetOrigin = ") {
		t.Fatalf("expected targetOrigin variable")
	}
	if !strings.Contains(html, `var targetOrigin = "https://example.com\";alert(1);//";`) {
		t.Fatalf("expected JSON-escaped origin in JS string literal, got: %s", html)
	}
}

func TestBuildOAuthPopupHTML_UsesSafeTargetOrigin(t *testing.T) {
	payload := []byte(`{"access_token":"abc"}`)

	origin := `https://example.com";alert(1);//`
	html := string(buildOAuthPopupHTML(payload, origin))

	if strings.Contains(html, "postMessage(data, '") {
		t.Fatalf("expected not to embed origin in single-quoted JS string")
	}
	if !strings.Contains(html, "var targetOrigin = ") {
		t.Fatalf("expected targetOrigin variable")
	}
	if !strings.Contains(html, `var targetOrigin = "https://example.com\";alert(1);//";`) {
		t.Fatalf("expected JSON-escaped origin in JS string literal, got: %s", html)
	}
}
