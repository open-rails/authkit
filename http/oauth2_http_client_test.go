package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/stretchr/testify/require"
)

func TestOAuth2OutboundHTTPClientHasTimeout(t *testing.T) {
	require.NotNil(t, oauth2OutboundHTTPClient)
	require.Equal(t, oauth2OutboundTimeout, oauth2OutboundHTTPClient.Timeout)
}

func TestOAuth2OutboundHTTPClientUsedByUserInfoFetch(t *testing.T) {
	orig := oauth2OutboundHTTPClient
	t.Cleanup(func() { oauth2OutboundHTTPClient = orig })

	var usedClient *http.Client
	oauth2OutboundHTTPClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			usedClient = oauth2OutboundHTTPClient
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
			UserMapping: authprovider.UserMapping{
				Subject: authprovider.FieldMapping{Path: "id", Transforms: []string{"string"}},
			},
		},
		oauth2TokenResp{AccessToken: "tok", TokenType: "Bearer"},
	)
	require.NoError(t, err)
	require.Equal(t, oauth2OutboundHTTPClient, usedClient)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
