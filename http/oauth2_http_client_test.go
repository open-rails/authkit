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
			UserMapping: authprovider.UserMapping{
				Subject: authprovider.FieldMapping{Path: "id", Transforms: []string{"string"}},
			},
		},
		oauth2TokenResp{AccessToken: "tok", TokenType: "Bearer"},
	)
	require.NoError(t, err)
	require.Equal(t, defaultOutboundHTTPClient, usedClient)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
