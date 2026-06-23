package authprovider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// AK security audit F4: the GitHub provider must not assume an email is verified.
// GitHub's /user.email is a public profile field with no verification guarantee,
// and the /user/emails fallback must reflect the real per-address `verified` flag.

func TestGitHubProvider_PrimaryEmailNotAssumedVerified(t *testing.T) {
	p, ok := BuiltIn("github")
	require.True(t, ok)

	// A typical /user response: carries an email but NO email_verified field.
	root := map[string]any{
		"id":    float64(123),
		"email": "user@example.com",
		"login": "octocat",
		"name":  "Octo Cat",
	}
	id, err := MapIdentity(root, p.UserMapping)
	require.NoError(t, err)
	require.Equal(t, "user@example.com", id.Email)
	require.False(t, id.EmailVerified, "GitHub /user.email must NOT be assumed verified (AK F4)")
}

func TestGitHubProvider_FallbackReflectsRealVerifiedFlag(t *testing.T) {
	p, ok := BuiltIn("github")
	require.True(t, ok)
	require.NotNil(t, p.EmailFallback)

	// /user/emails: only a primary AND verified entry is selected, and the mapped
	// verified flag comes from the real per-address field.
	emails := []any{
		map[string]any{"email": "secondary@example.com", "primary": false, "verified": true},
		map[string]any{"email": "primary@example.com", "primary": true, "verified": true},
	}
	email, verified := MapFallbackEmail(emails, *p.EmailFallback)
	require.Equal(t, "primary@example.com", email)
	require.True(t, verified)

	// An unverified primary address is not selected (Select requires verified=true),
	// so no email is returned — it can never be promoted to "verified".
	unverified := []any{
		map[string]any{"email": "primary@example.com", "primary": true, "verified": false},
	}
	email2, verified2 := MapFallbackEmail(unverified, *p.EmailFallback)
	require.Equal(t, "", email2)
	require.False(t, verified2)
}
