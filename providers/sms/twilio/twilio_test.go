package twilio

import (
	"bytes"
	"context"
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
	if _, err := New(Config{AccountSID: "AC123", AuthToken: "secret"}); err == nil {
		t.Fatalf("expected missing messaging service SID to fail validation")
	}
}

func TestSendVerificationUsesMessagingAPIWithCodeAndLink(t *testing.T) {
	var gotURL string
	var gotBody string
	var gotUser string
	var gotPass string

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotUser, gotPass, _ = r.BasicAuth()
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		AccountSID:          " AC123 ",
		AuthToken:           " secret ",
		MessagingServiceSID: " MG123 ",
		AppName:             "Example",
		Client:              client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = s.SendVerification(context.Background(), "+15555550123", core.VerificationMessage{
		Code:    "123456",
		LinkURL: "https://example.com/verify?token=verify-token",
	})
	if err != nil {
		t.Fatalf("SendVerification: %v", err)
	}
	if !strings.Contains(gotURL, "/2010-04-01/Accounts/AC123/Messages.json") {
		t.Fatalf("expected Twilio Messaging API URL, got %q", gotURL)
	}
	if strings.Contains(gotURL, "verify.twilio.com") {
		t.Fatalf("must not use Twilio Verify API, got %q", gotURL)
	}
	if gotUser != "AC123" || gotPass != "secret" {
		t.Fatalf("unexpected basic auth: %q/%q", gotUser, gotPass)
	}
	for _, want := range []string{"MessagingServiceSid=MG123", "123456", "https%3A%2F%2Fexample.com%2Fverify%3Ftoken%3Dverify-token"} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("expected request body to contain %q, got %s", want, gotBody)
		}
	}
	if strings.Contains(gotBody, "From=") {
		t.Fatalf("must not use From-number fallback, got %s", gotBody)
	}
}

func TestCustomBuilders(t *testing.T) {
	var gotBody string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		AccountSID:          "AC123",
		AuthToken:           "secret",
		MessagingServiceSID: "MG123",
		Client:              client,
		LoginCodeBuilder: func(ctx context.Context, phone, code string) string {
			return "custom login " + code + " for " + phone
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SendLoginCode(context.Background(), "+15555550123", "654321"); err != nil {
		t.Fatalf("SendLoginCode: %v", err)
	}
	if !strings.Contains(gotBody, "custom+login+654321") {
		t.Fatalf("expected custom body, got %s", gotBody)
	}
}

func TestDefaultMessagesUseContextLanguage(t *testing.T) {
	var bodies []string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}

	s, err := New(Config{
		AccountSID:          "AC123",
		AuthToken:           "secret",
		MessagingServiceSID: "MG123",
		AppName:             "Doujins",
		Client:              client,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	esCtx := authlang.WithLanguage(context.Background(), "es")
	if err := s.SendLoginCode(esCtx, "+15555550123", "654321"); err != nil {
		t.Fatalf("SendLoginCode es: %v", err)
	}
	if !strings.Contains(bodies[0], "Doujins+codigo+de+inicio%3A+654321") {
		t.Fatalf("expected Spanish SMS body, got %s", bodies[0])
	}

	frCtx := authlang.WithLanguage(context.Background(), "fr")
	if err := s.SendLoginCode(frCtx, "+15555550123", "654321"); err != nil {
		t.Fatalf("SendLoginCode fallback: %v", err)
	}
	if !strings.Contains(bodies[1], "Doujins+login+code%3A+654321") {
		t.Fatalf("expected English fallback SMS body, got %s", bodies[1])
	}
}
