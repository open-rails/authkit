package apitest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/internal/httpapi"
)

// createdFactorID is a POST /me/2fa/factors answer's factor id.
func (s authAnswer) createdFactorID(t testing.TB) string {
	t.Helper()
	var created httpapi.TwoFactorFactorCreated
	require.NoError(t, json.Unmarshal([]byte(s.raw), &created), s.raw)
	require.NotEmpty(t, created.Factor.ID, s.raw)
	return created.Factor.ID
}

// signInKeys lists token's caller's sign-in keys of kind ("" = every kind).
func (f *factorFlow) signInKeys(token string, kind httpapi.SignInKeyKind) []httpapi.SignInKey {
	f.t.Helper()
	var listed struct {
		Data []httpapi.SignInKey `json:"data"`
	}
	res := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/sign-in-keys", token, nil))
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &listed), res.raw)
	out := []httpapi.SignInKey{}
	for _, key := range listed.Data {
		if kind == "" || key.Kind == kind {
			out = append(out, key)
		}
	}
	return out
}
