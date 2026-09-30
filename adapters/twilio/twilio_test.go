package twilio_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/open-rails/authkit/adapters/twilio"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// recorder stands in for the provider: it keeps each request body and answers
// with a canned response.
type recorder struct {
	status int
	reply  string
	bodies []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r.bodies = append(r.bodies, string(b))
	return &http.Response{StatusCode: r.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(r.reply)), Request: req}, nil
}

func TestEmailRenderFallsBackPerKind(t *testing.T) {
	rec := &recorder{status: http.StatusAccepted}
	email, err := twilio.NewEmail(twilio.EmailConfig{
		APIKey:    "SG.key",
		FromEmail: "hello@acme.test",
		AppName:   "Acme",
		Client:    &http.Client{Transport: rec},
		Render: func(_ context.Context, msg iam.EmailMessage) (twilio.EmailContent, bool) {
			if msg.Kind != iam.MessageLoginCode {
				return twilio.EmailContent{}, false
			}
			return twilio.EmailContent{Subject: "Acme sign-in", Text: "Your code is " + msg.Code}, true
		},
	})
	require.NoError(t, err)

	type payload struct {
		Personalizations []struct{ Subject string }
		Content          []struct{ Type, Value string }
		Categories       []string
	}
	send := func(msg iam.EmailMessage) payload {
		t.Helper()
		msg.To = "ana@acme.test"
		require.NoError(t, email.Send(t.Context(), msg))
		var p payload
		require.NoError(t, json.Unmarshal([]byte(rec.bodies[len(rec.bodies)-1]), &p))
		return p
	}

	got := send(iam.EmailMessage{Kind: iam.MessageLoginCode, Language: "en", Code: "123456"})
	require.Equal(t, "Acme sign-in", got.Personalizations[0].Subject)
	require.Equal(t, "Your code is 123456", got.Content[0].Value)

	got = send(iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "en", Link: "https://acme.test/reset"})
	require.Equal(t, "Reset your Acme password", got.Personalizations[0].Subject)
	require.Equal(t, "Use this link to reset your password:\nhttps://acme.test/reset", got.Content[0].Value)
	require.Equal(t, []string{"auth", "password-reset"}, got.Categories)

	got = send(iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "es", Link: "https://acme.test/reset"})
	require.Equal(t, "Restablece tu contrasena de Acme", got.Personalizations[0].Subject)

	err = email.Send(t.Context(), iam.EmailMessage{Kind: "carrier_pigeon", To: "ana@acme.test"})
	require.ErrorContains(t, err, "carrier_pigeon")
	require.Len(t, rec.bodies, 3, "an unknown kind reaches no provider")
}

func TestSMSRenderFallsBackPerKind(t *testing.T) {
	rec := &recorder{status: http.StatusCreated, reply: `{"sid":"SM1","status":"sent"}`}
	sms, err := twilio.NewSMS(twilio.SMSConfig{
		AccountSID:          "AC1",
		AuthToken:           "token",
		MessagingServiceSID: "MG1",
		AppName:             "Acme",
		Client:              &http.Client{Transport: rec},
		Render: func(_ context.Context, msg iam.SMSMessage) (string, bool) {
			return "Acme: " + msg.Code, msg.Kind == iam.MessageLoginCode
		},
	})
	require.NoError(t, err)
	body := func(msg iam.SMSMessage) string {
		t.Helper()
		msg.To = "+15551230000"
		require.NoError(t, sms.Send(t.Context(), msg))
		form, err := url.ParseQuery(rec.bodies[len(rec.bodies)-1])
		require.NoError(t, err)
		return form.Get("Body")
	}

	require.Equal(t, "Acme: 123456", body(iam.SMSMessage{Kind: iam.MessageLoginCode, Language: "en", Code: "123456"}))
	require.Equal(t, "Acme codigo de verificacion: 654321", body(iam.SMSMessage{Kind: iam.MessageVerification, Language: "es", Code: "654321", Purpose: iam.PurposeSignup}))
	require.Error(t, sms.Send(t.Context(), iam.SMSMessage{Kind: iam.MessageVerification, To: "+15551230000"}), "a verification needs a code or a link")
}
