package authhttp

import (
	"encoding/json"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/stretchr/testify/require"
)

// requireErrorCode decodes the Stripe-style error envelope (#115) and asserts
// the machine-readable code, plus that type and message are always populated.
// Replaces the old flat `{"error":"<code>"}` JSONEq assertions.
func requireErrorCode(t *testing.T, body, code string) {
	t.Helper()
	var env authkit.ErrorEnvelope
	require.NoError(t, json.Unmarshal([]byte(body), &env), "error body: %s", body)
	require.Equal(t, code, env.Error.Code, "error body: %s", body)
	require.NotEmpty(t, env.Error.Type, "error.type must be set")
	require.NotEmpty(t, env.Error.Message, "error.message must be set")
}
