package smtp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/adapters/smtp"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/helpers/smtp/smtptest"
	"github.com/stretchr/testify/require"
)

const password = "SG.test-api-key"

// email is the adapter on srv, as SendGrid is reached: STARTTLS on the
// submission port, username "apikey".
func email(t *testing.T, srv *smtptest.Server, render func(context.Context, iam.EmailMessage) (smtp.Content, bool)) *smtp.Email {
	t.Helper()
	e, err := smtp.New(smtp.Config{
		Server: smtp.Server{Host: srv.Host, Port: srv.Port, Username: "apikey", Password: password,
			From: "Acme <hello@acme.test>", TLS: srv.ClientTLS()},
		AppName: "Acme",
		Render:  render,
	})
	require.NoError(t, err)
	return e
}

func server(t *testing.T) *smtptest.Server {
	return smtptest.Start(t, smtptest.Options{Username: "apikey", Password: password, STARTTLS: true})
}

func TestRenderFallsBackPerKind(t *testing.T) {
	srv := server(t)
	e := email(t, srv, func(_ context.Context, msg iam.EmailMessage) (smtp.Content, bool) {
		if msg.Kind != iam.MessageLoginCode {
			return smtp.Content{}, false
		}
		return smtp.Content{Subject: "Acme sign-in", Text: "Your code is " + msg.Code}, true
	})
	send := func(msg iam.EmailMessage) smtptest.Message {
		t.Helper()
		msg.To = "ana@acme.test"
		n := len(srv.Messages())
		require.NoError(t, e.Send(t.Context(), msg))
		return srv.Wait(t, n+1, 5*time.Second)[n]
	}

	got := send(iam.EmailMessage{Kind: iam.MessageLoginCode, Language: "en", Code: "123456"})
	require.Equal(t, "Acme sign-in", got.Subject)
	require.Equal(t, "Your code is 123456\n", got.Text)
	require.Equal(t, []string{"ana@acme.test"}, got.To)
	require.Equal(t, "hello@acme.test", got.From)
	require.True(t, got.TLS)

	got = send(iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "en", Link: "https://acme.test/reset"})
	require.Equal(t, "Reset your Acme password", got.Subject)
	require.Equal(t, "Use this link to reset your password:\nhttps://acme.test/reset", got.Text)
	require.Contains(t, got.HTML, "https://acme.test/reset")

	got = send(iam.EmailMessage{Kind: iam.MessagePasswordReset, Language: "es", Link: "https://acme.test/reset"})
	require.Equal(t, "Restablece tu contrasena de Acme", got.Subject)

	err := e.Send(t.Context(), iam.EmailMessage{Kind: "carrier_pigeon", To: "ana@acme.test"})
	require.ErrorContains(t, err, "carrier_pigeon")
	require.ErrorContains(t, e.Send(t.Context(), iam.EmailMessage{Kind: iam.MessageVerification, To: "ana@acme.test"}), "code or a link")
	require.Len(t, srv.Messages(), 3, "an unknown kind or an empty verification reaches no server")
}

func TestNewNeedsHostAndFrom(t *testing.T) {
	_, err := smtp.New(smtp.Config{Server: smtp.Server{Host: "smtp.sendgrid.net"}})
	require.ErrorContains(t, err, "from is required")
	_, err = smtp.New(smtp.Config{Server: smtp.Server{From: "hello@acme.test"}})
	require.ErrorContains(t, err, "host is required")
}

// A sign-up completed with the code AuthKit mailed: the real adapter, over
// STARTTLS with credentials, into an SMTP server.
func TestSignUpCodeArrivesBySMTP(t *testing.T) {
	srv := server(t)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.Verification = iam.RegistrationVerificationRequired
	}), authtest.WithDeps(func(d *authkit.Deps) { d.Email = email(t, srv, nil) }))
	require.NoError(t, auth.Start(t.Context()))
	api := httptest.NewServer(auth.Handler())
	t.Cleanup(api.Close)
	post := func(path, body string) int {
		resp, err := http.Post(api.URL+"/api/v1"+path, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	const to = "carol@example.com"
	require.Equal(t, http.StatusAccepted, post("/register", `{"identifier":"`+to+`","username":"carol","password":"`+authtest.Password+`"}`))
	m := srv.Wait(t, 1, 10*time.Second)[0]
	require.Equal(t, []string{to}, m.To)
	require.Equal(t, "apikey", m.Username)
	require.Equal(t, "Verify your Acme account", m.Subject)
	code := regexp.MustCompile(`Code: (\S+)`).FindStringSubmatch(m.Text)
	require.Len(t, code, 2, "the text body carries the code: %q", m.Text)
	require.Contains(t, m.HTML, code[1])

	require.Equal(t, http.StatusOK, post("/verify/confirm", `{"identifier":"`+to+`","code":"`+code[1]+`"}`))
	require.NotEmpty(t, authtest.SignIn(t, auth, authtest.User{Email: to, Password: authtest.Password}).AccessToken)
}
