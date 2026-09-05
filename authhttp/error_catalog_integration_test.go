package authhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
)

// One error model (ak#290): every catalogued code leaves the one writer with
// its catalog status, type and message, wrapped or not; a status-500 code is
// internal_error on the wire; param and metadata ride on the error itself.
func TestErrorCatalogThroughWriter(t *testing.T) {
	t.Parallel()
	for _, code := range authkit.Codes() {
		status, message, ok := authkit.DescribeCode(code)
		require.True(t, ok, code)
		w := httptest.NewRecorder()
		writeError(w, fmt.Errorf("wrapped: %w", authkit.E(code)))
		require.Equal(t, status, w.Code, code)
		var env authkit.ErrorEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), code)
		require.Equal(t, authkit.ErrorTypeForStatus(status), env.Error.Type, code)
		require.NotEmpty(t, env.Error.Message, code)
		if status == http.StatusInternalServerError {
			require.Equal(t, "internal_error", env.Error.Code, code)
			continue
		}
		require.Equal(t, code.String(), env.Error.Code)
		require.Equal(t, message, env.Error.Message, code)
	}

	w := httptest.NewRecorder()
	writeError(w, authkit.E(authkit.CodeInvalidEmail, authkit.WithMeta("hint", "x")))
	var env authkit.ErrorEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.NotNil(t, env.Error.Param)
	require.Equal(t, "email", *env.Error.Param, "a validation code carries its catalogued param")
	require.Equal(t, "x", env.Error.Metadata["hint"])

	w = httptest.NewRecorder()
	writeError(w, remap(authkit.ErrPasskeyNotFound, notFoundCodes))
	require.Equal(t, http.StatusNotFound, w.Code)
	requireErrorCode(t, w.Body.String(), "not_found")

	w = httptest.NewRecorder()
	writeError(w, fallback(fmt.Errorf("authorizer down"), authkit.CodeDelegationAuthorizerUnavailable))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	requireErrorCode(t, w.Body.String(), "delegation_authorizer_unavailable")

	w = httptest.NewRecorder()
	writeError(w, fallback(authkit.ErrDelegationRefused, authkit.CodeDelegationAuthorizerUnavailable))
	require.Equal(t, http.StatusForbidden, w.Code, "a catalogued 4xx keeps its code through fallback")
	requireErrorCode(t, w.Body.String(), "delegation_refused")
}

// A mounted route answers exactly what the catalog says for the code it emits.
func TestErrorCatalogThroughMountedRoutes(t *testing.T) {
	srv := newTestService(t)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/register/availability", "", http.StatusBadRequest},
		{http.MethodGet, "/me", "", http.StatusUnauthorized},
		{http.MethodPost, "/register", `{"identifier":"not an identifier","username":"catalogwalk","password":"Password123!"}`, 0},
	} {
		w := serveJSON(srv, tc.method, tc.path, tc.body)
		if tc.status != 0 {
			require.Equal(t, tc.status, w.Code, "%s %s: %s", tc.method, tc.path, w.Body.String())
		}
		require.True(t, w.Code >= 400 && w.Code < 500, "%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		var env authkit.ErrorEnvelope
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
		status, message, ok := authkit.DescribeCode(authkit.Code(env.Error.Code))
		require.True(t, ok, "%s %s emitted uncatalogued code %q", tc.method, tc.path, env.Error.Code)
		require.Equal(t, status, w.Code, env.Error.Code)
		require.Equal(t, message, env.Error.Message, env.Error.Code)
		require.Equal(t, authkit.ErrorTypeForStatus(status), env.Error.Type, env.Error.Code)
	}
}
