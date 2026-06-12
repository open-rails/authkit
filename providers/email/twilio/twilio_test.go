package twilio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	core "github.com/open-rails/authkit/core"
	authlang "github.com/open-rails/authkit/lang"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatalf("expected empty config to fail validation")
	}
	if _, err := New(Config{APIKey: "SG.x"}); err == nil {
		t.Fatalf("expected missing from email to fail validation")
	}
}

func TestSendVerificationPayload(t *testing.T) {
	var gotAuth string
	var gotContentType string
	var payload map[string]any

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if r.URL.String() != sendGridMailSendURL {
			t.Fatalf("unexpected URL: %s", r.URL.String())
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("decode payload: %v\n%s", err, string(b))
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewBufferString(``)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		APIKey:    " SG.key ",
		FromEmail: " noreply@example.com ",
		FromName:  " Example ",
		AppName:   "Example",
		Client:    client,
		Categories: []string{
			"platform",
		},
		CustomArgs: map[string]string{"tenant": "cozy-art"},
		VerificationLinkURL: func(token string) string {
			return "https://example.com/verify?token=" + token
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = s.SendVerification(context.Background(), "user@example.com", "alice", core.VerificationMessage{
		Code:      "123456",
		LinkToken: "verify-token",
	})
	if err != nil {
		t.Fatalf("SendVerification: %v", err)
	}
	if gotAuth != "Bearer SG.key" {
		t.Fatalf("unexpected auth header %q", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Fatalf("unexpected content-type %q", gotContentType)
	}
	assertNestedString(t, payload, []string{"from", "email"}, "noreply@example.com")
	assertNestedString(t, payload, []string{"from", "name"}, "Example")
	if !payloadContains(t, payload, "user@example.com") {
		t.Fatalf("expected recipient in payload: %#v", payload)
	}
	for _, want := range []string{"123456", "https://example.com/verify?token=verify-token"} {
		if !payloadContains(t, payload, want) {
			t.Fatalf("expected payload to contain %q: %#v", want, payload)
		}
	}
	if !payloadContains(t, payload, "platform") || !payloadContains(t, payload, "email-verification") {
		t.Fatalf("expected merged categories in payload: %#v", payload)
	}
	if !payloadContains(t, payload, "cozy-art") {
		t.Fatalf("expected custom args in payload: %#v", payload)
	}
}

func TestCustomBuilderPayload(t *testing.T) {
	var payload map[string]any
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewBufferString(``)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		APIKey:    "SG.key",
		FromEmail: "noreply@example.com",
		Client:    client,
		LoginCodeBuilder: func(ctx context.Context, email, username, code string) Message {
			return Message{
				Subject:    "custom subject",
				TextBody:   "custom text " + code,
				HTMLBody:   "<p>custom html " + code + "</p>",
				Categories: []string{"custom-category"},
				CustomArgs: map[string]string{"flow": "login"},
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SendLoginCode(context.Background(), "user@example.com", "alice", "654321"); err != nil {
		t.Fatalf("SendLoginCode: %v", err)
	}
	for _, want := range []string{"custom subject", "custom text 654321", "custom html 654321", "custom-category", "login"} {
		if !payloadContains(t, payload, want) {
			t.Fatalf("expected payload to contain %q: %#v", want, payload)
		}
	}
}

func TestDefaultMessagesUseContextLanguage(t *testing.T) {
	var payloads []map[string]any
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload map[string]any
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		payloads = append(payloads, payload)
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(bytes.NewBufferString(``)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		APIKey:    "SG.key",
		FromEmail: "noreply@example.com",
		AppName:   "Doujins",
		Client:    client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	esCtx := authlang.WithLanguage(context.Background(), "es")
	if err := s.SendLoginCode(esCtx, "user@example.com", "alice", "654321"); err != nil {
		t.Fatalf("SendLoginCode es: %v", err)
	}
	if !payloadContains(t, payloads[0], "Tu codigo de inicio de sesion de Doujins") {
		t.Fatalf("expected Spanish login-code payload: %#v", payloads[0])
	}

	frCtx := authlang.WithLanguage(context.Background(), "fr")
	if err := s.SendLoginCode(frCtx, "user@example.com", "alice", "654321"); err != nil {
		t.Fatalf("SendLoginCode fallback: %v", err)
	}
	if !payloadContains(t, payloads[1], "Your Doujins login code") {
		t.Fatalf("expected English fallback payload: %#v", payloads[1])
	}
}

func assertNestedString(t *testing.T, payload map[string]any, path []string, want string) {
	t.Helper()
	var cur any = payload
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("expected object at %v in %#v", path, payload)
		}
		cur = m[key]
	}
	if cur != want {
		t.Fatalf("got %q, want %q at %v", cur, want, path)
	}
}

func payloadContains(t *testing.T, payload map[string]any, want string) bool {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return strings.Contains(string(b), want)
}
