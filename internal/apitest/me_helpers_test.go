package apitest_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// createdAuth reads a POST /me/2fa/factors answer's auth (an AuthResult) as
// an authAnswer: the sign-in an enrollment token finished, or the session's
// fresh token. Zero when auth is null.
func (s authAnswer) createdAuth(t testing.TB) authAnswer {
	t.Helper()
	var body struct {
		Auth json.RawMessage `json:"auth"`
	}
	require.NoError(t, json.Unmarshal([]byte(s.raw), &body), s.raw)
	out := authAnswer{status: s.status, raw: string(body.Auth)}
	if len(body.Auth) > 0 && string(body.Auth) != "null" {
		require.NoError(t, json.Unmarshal(body.Auth, &out), s.raw)
	}
	return out
}

// createdFactorID is a POST /me/2fa/factors answer's factor id.
func (s authAnswer) createdFactorID(t testing.TB) string {
	t.Helper()
	var body struct {
		Factor struct {
			ID string `json:"id"`
		} `json:"factor"`
	}
	require.NoError(t, json.Unmarshal([]byte(s.raw), &body), s.raw)
	require.NotEmpty(t, body.Factor.ID, s.raw)
	return body.Factor.ID
}

// signInKey is one entry of GET /me/sign-in-keys.
type signInKey struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Label      *string    `json:"label"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Current    bool       `json:"current"`
}

// signInKeys lists token's caller's sign-in keys of kind ("" = every kind).
func (f *factorFlow) signInKeys(token, kind string) []signInKey {
	f.t.Helper()
	var listed struct {
		Data []signInKey `json:"data"`
	}
	res := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/sign-in-keys", token, nil))
	require.NoError(f.t, json.Unmarshal([]byte(res.raw), &listed), res.raw)
	out := []signInKey{}
	for _, key := range listed.Data {
		if kind == "" || key.Kind == kind {
			out = append(out, key)
		}
	}
	return out
}
