package authhttp

import (
	"encoding/json"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// passwordlessTokenBody lifts {"token_set": ..., "return_to"?} (#313) into
// flat fields.
type passwordlessTokenBody struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	ReturnTo     string
}

func (b *passwordlessTokenBody) UnmarshalJSON(raw []byte) error {
	var env struct {
		TokenSet authkit.TokenSet `json:"token_set"`
		ReturnTo string           `json:"return_to"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	*b = passwordlessTokenBody{AccessToken: env.TokenSet.AccessToken, TokenType: env.TokenSet.TokenType, ExpiresIn: env.TokenSet.ExpiresIn, RefreshToken: env.TokenSet.RefreshToken, ReturnTo: env.ReturnTo}
	return nil
}

func passwordlessTestServer(t *testing.T, autoRegister bool) (*Service, *captureEmailSender, *captureSMSSender) {
	t.Helper()
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.Frontend.PasswordlessPath = "/wallet/login"
	cfg.Registration.PasswordlessLogin = true
	cfg.Registration.PasswordlessAutoRegistration = autoRegister
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(emailSender), withSMSSender(smsSender)), WithoutRateLimiter())
	require.NoError(t, err)
	return srv, emailSender, smsSender
}
