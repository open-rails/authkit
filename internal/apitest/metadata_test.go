package apitest_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// PatchPublicMetadata is an RFC 7396 JSON Merge Patch: objects merge
// recursively, null deletes a key at any depth, and any other value, an
// array or a scalar, replaces what it names.
func TestPatchPublicMetadataIsAMergePatch(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx := t.Context()
	u := authtest.NewUser(t, auth)
	// apply patches with patch (JSON, or a Go value) and returns the stored
	// public metadata as JSON.
	apply := func(t *testing.T, patch any) string {
		t.Helper()
		p, ok := patch.(map[string]any)
		if !ok {
			require.NoError(t, json.Unmarshal([]byte(patch.(string)), &p))
		}
		require.NoError(t, auth.PatchPublicMetadata(ctx, iam.SystemActor(), u.ID, p))
		got, err := auth.User(ctx, iam.UserByID(u.ID))
		require.NoError(t, err)
		raw, err := json.Marshal(got.PublicMetadata)
		require.NoError(t, err)
		return string(raw)
	}

	require.JSONEq(t, `{"prefs":{"theme":"dark","lang":"en","beta":true},"tier":"gold","tags":["a","b"]}`,
		apply(t, `{"prefs":{"theme":"dark","lang":"en","beta":true},"tier":"gold","tags":["a","b"]}`))
	require.JSONEq(t, `{"prefs":{"theme":"light","lang":"en","beta":true,"font":{"face":"serif"}},"tier":"gold","tags":["a","b"]}`,
		apply(t, `{"prefs":{"theme":"light","font":{"face":"serif"}}}`), "a nested object merges into the stored one")
	require.JSONEq(t, `{"prefs":{"theme":"light","lang":"en","font":{}},"tier":"gold","tags":["a","b"]}`,
		apply(t, `{"prefs":{"beta":null,"font":{"face":null}}}`), "null deletes a nested key")
	require.JSONEq(t, `{"prefs":{"theme":"light","lang":"en","font":{}},"tier":{"name":"gold","since":2024},"tags":["c"]}`,
		apply(t, `{"tier":{"name":"gold","since":2024},"tags":["c"]}`), "an object replaces a scalar; an array replaces an array whole")
	require.JSONEq(t, `{"prefs":"reset","tier":{"name":"gold","since":2024}}`,
		apply(t, `{"prefs":"reset","tags":null}`), "a scalar replaces an object; null deletes a top-level key")
	require.JSONEq(t, `{"prefs":{"theme":"dark"},"tier":{"name":"gold","since":2024}}`,
		apply(t, map[string]any{"prefs": map[string]string{"theme": "dark"}}), "a Go value merges as its JSON")
}
