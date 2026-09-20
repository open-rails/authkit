package verify_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

type optionalLiveSource struct {
	calls   int
	allowed bool
	err     error
}

func (s *optionalLiveSource) UserLivenessByIDs(_ context.Context, ids []string) (map[string]authkit.UserLiveness, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return map[string]authkit.UserLiveness{ids[0]: {ID: ids[0], Allowed: s.allowed, Username: "fresh"}}, nil
}

func TestOptionalLive(t *testing.T) {
	for _, verifier := range []*verify.Verifier{nil, verify.NewVerifier()} {
		middleware, err := verify.OptionalLive(verifier)
		require.Nil(t, middleware)
		require.ErrorIs(t, err, verify.ErrLivenessUnconfigured)
	}
	issuer := authtest.NewTestIssuer()
	defer issuer.Close()
	token := issuer.CreateToken("user-1", "old@example.test")
	for _, tc := range []struct {
		name, header   string
		local, allowed bool
		sourceErr      error
		status, calls  int
	}{
		{name: "anonymous", local: true, status: 200},
		{name: "invalid credential", header: "Bearer invalid", local: true, status: 401},
		{name: "live user", header: "Bearer " + token, local: true, allowed: true, status: 200, calls: 1},
		{name: "banned user", header: "Bearer " + token, local: true, status: 401, calls: 1},
		{name: "backend unavailable", header: "Bearer " + token, local: true, sourceErr: errors.New("directory unavailable"), status: 401, calls: 1},
		{name: "external principal", header: "Bearer " + token, sourceErr: errors.New("must not query native accounts"), status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &optionalLiveSource{allowed: tc.allowed, err: tc.sourceErr}
			verifier := verify.NewVerifier().WithLiveness(source)
			require.NoError(t, verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, verify.IssuerOptions{JWKSURI: issuer.URL() + "/.well-known/jwks.json", IsLocal: tc.local}))
			middleware, err := verify.OptionalLive(verifier)
			require.NoError(t, err)
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				claims, present := verify.ClaimsFromContext(r.Context())
				require.Equal(t, tc.header != "", present)
				if tc.local && present {
					require.Equal(t, "fresh", claims.Username)
				}
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", tc.header)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			require.Equal(t, tc.calls, source.calls)
		})
	}
}
