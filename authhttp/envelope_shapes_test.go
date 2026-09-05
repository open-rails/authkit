package authhttp

// #313 wire-shape helpers: pending-challenge outcomes are 403 error envelopes
// with the challenge in metadata; composite session responses nest the
// TokenSet under "token_set".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

type twoFAChallenge struct {
	UserID    string
	Method    string
	Challenge string
}

// requireTwoFARequired decodes the 403 2fa_required envelope.
func requireTwoFARequired(t *testing.T, w *httptest.ResponseRecorder) twoFAChallenge {
	t.Helper()
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var body struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				UserID    string `json:"user_id"`
				Method    string `json:"method"`
				Challenge string `json:"challenge"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, string(authkit.CodeTwoFARequired), body.Error.Code)
	return twoFAChallenge{UserID: body.Error.Metadata.UserID, Method: body.Error.Metadata.Method, Challenge: body.Error.Metadata.Challenge}
}

// requireEnrollmentToken decodes the 403 2fa_enrollment_required envelope and
// returns the enrollment-only access token it carries.
func requireEnrollmentToken(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var body struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				TokenSet authkit.TokenSet `json:"token_set"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, string(authkit.CodeTwoFAEnrollmentRequired), body.Error.Code)
	require.NotEmpty(t, body.Error.Metadata.TokenSet.AccessToken)
	return body.Error.Metadata.TokenSet.AccessToken
}

// nestedTokenBody decodes a composite response ({"token_set": ...}) into the
// flat token fields older assertions read.
type nestedTokenBody struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
}

func (b *nestedTokenBody) UnmarshalJSON(raw []byte) error {
	var env struct {
		TokenSet authkit.TokenSet `json:"token_set"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	b.AccessToken, b.TokenType, b.ExpiresIn = env.TokenSet.AccessToken, env.TokenSet.TokenType, env.TokenSet.ExpiresIn
	return nil
}
