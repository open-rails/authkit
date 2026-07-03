package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDefaultOutboundHTTPClientHasTimeout(t *testing.T) {
	require.NotNil(t, defaultOutboundHTTPClient)
	require.Equal(t, DefaultOutboundTimeout, defaultOutboundHTTPClient.Timeout)
}

func TestOAuth2UserInfoFetchUsesDefaultOutboundClient(t *testing.T) {
	orig := defaultOutboundHTTPClient
	t.Cleanup(func() { defaultOutboundHTTPClient = orig })

	var usedClient *http.Client
	defaultOutboundHTTPClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			usedClient = defaultOutboundHTTPClient
			return http.DefaultTransport.RoundTrip(r)
		}),
		Timeout: 5 * time.Second,
	}

	s := newTestService(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "1"})
	}))
	defer ts.Close()

	_, err := s.fetchOAuthUserInfo(
		httptest.NewRequest(http.MethodGet, "/", nil),
		authprovider.Provider{
			Name:        "probe",
			Kind:        authprovider.KindOAuth2,
			UserInfoURL: ts.URL,
			IdentityMapper: func(root any) (authprovider.Identity, error) {
				m, _ := root.(map[string]any)
				id, _ := m["id"].(string)
				return authprovider.Identity{Subject: id}, nil
			},
		},
		oauth2TokenResp{AccessToken: "tok", TokenType: "Bearer"},
	)
	require.NoError(t, err)
	require.Equal(t, defaultOutboundHTTPClient, usedClient)
}

// AK security audit F4: only a primary AND verified address is selected from the
// GitHub /user/emails fallback, and an unverified primary can never be promoted.
func TestSelectPrimaryVerifiedEmail(t *testing.T) {
	verified := []any{
		map[string]any{"email": "secondary@example.com", "primary": false, "verified": true},
		map[string]any{"email": "primary@example.com", "primary": true, "verified": true},
	}
	email, ok := selectPrimaryVerifiedEmail(verified)
	require.Equal(t, "primary@example.com", email)
	require.True(t, ok)

	// An unverified primary address is not selected — no email returned.
	unverified := []any{
		map[string]any{"email": "primary@example.com", "primary": true, "verified": false},
	}
	email, ok = selectPrimaryVerifiedEmail(unverified)
	require.Equal(t, "", email)
	require.False(t, ok)

	// A non-array payload yields nothing.
	email, ok = selectPrimaryVerifiedEmail(map[string]any{"email": "x@example.com"})
	require.Equal(t, "", email)
	require.False(t, ok)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
