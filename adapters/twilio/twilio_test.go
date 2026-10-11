package twilio_test

import (
	"context"
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

// A code message ends with its origin-bound line (WICG origin-bound one-time
// codes), so browsers autofill it only on the domain AuthKit names; a message
// without a code, or without a domain, has none.
func TestSMSCodeIsOriginBound(t *testing.T) {
	rec := &recorder{status: http.StatusCreated, reply: `{"sid":"SM1","status":"sent"}`}
	sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "AC1", AuthToken: "token", MessagingServiceSID: "MG1", AppName: "OpenRails",
		Client: &http.Client{Transport: rec}})
	require.NoError(t, err)
	body := func(msg iam.SMSMessage) string {
		t.Helper()
		msg.To = "+15551230000"
		require.NoError(t, sms.Send(t.Context(), msg))
		form, err := url.ParseQuery(rec.bodies[len(rec.bodies)-1])
		require.NoError(t, err)
		return form.Get("Body")
	}
	require.Equal(t, "OpenRails verification code: 123456\n\n@openrails.dev #123456",
		body(iam.SMSMessage{Kind: iam.MessageVerification, Code: "123456", Purpose: iam.PurposePasswordlessLogin, Domain: "openrails.dev"}))
	require.Equal(t, "OpenRails new device code: 654321. If this isn't you, change your password.\n\n@openrails.dev #654321",
		body(iam.SMSMessage{Kind: iam.MessageNewDeviceCode, Code: "654321", Domain: "openrails.dev"}))
	require.Equal(t, "OpenRails login code: 111222", body(iam.SMSMessage{Kind: iam.MessageLoginCode, Code: "111222"}))
	require.Equal(t, "OpenRails password reset: https://openrails.dev/reset#token=x",
		body(iam.SMSMessage{Kind: iam.MessagePasswordReset, Link: "https://openrails.dev/reset#token=x", Domain: "openrails.dev"}))
}
