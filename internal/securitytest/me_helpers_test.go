package securitytest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// createdSession is the session a POST /me/2fa/factors answer carries in its
// auth: the sign-in an enrollment token finished, or the re-verified
// session's fresh token.
func createdSession(t *testing.T, r response) tokens {
	t.Helper()
	var created struct {
		Auth *struct {
			TokenSet *tokens `json:"token_set"`
		} `json:"auth"`
	}
	r.json(t, &created)
	require.NotNil(t, created.Auth, r.String())
	require.NotNil(t, created.Auth.TokenSet, r.String())
	return *created.Auth.TokenSet
}
