package apitest_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// An unknown bootstrap manifest key is logged as a warning naming its path
// and ignored; an invalid value of a known key still fails the parse. It
// replaces the process logger, so it never runs in parallel.
func TestBootstrapManifestIgnoresUnknownKeys(t *testing.T) {
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	auth, _ := authtest.New(t)
	ctx := t.Context()

	manifest, err := auth.ParseBootstrapManifestYAML([]byte(`version: 2
users:
 - username: unknown-keys
   email: unknown-keys@example.test
   email_verified: true
   nickname: uk
   metadata: {anything: {goes: here}}
   password: {plaintext: bootstrap-password-1, rotate: true}
`))
	require.NoError(t, err)
	require.Contains(t, logs.String(), "level=WARN")
	for _, path := range []string{"version", "users[0].nickname", "users[0].password.rotate"} {
		require.Contains(t, logs.String(), `ignoring unknown key" path=`+path+"\n")
	}
	require.NotContains(t, logs.String(), "path=users[0].metadata", "metadata is free-form")
	require.NotContains(t, logs.String(), "path=users[0].email\n")

	result, err := auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.UsersCreated)
	u, err := auth.User(ctx, iam.UserByUsername("unknown-keys"))
	require.NoError(t, err)
	require.NotNil(t, u.Email)
	require.Equal(t, "unknown-keys@example.test", *u.Email)

	_, err = auth.ParseBootstrapManifestYAML([]byte("users:\n - {username: bad, email_verified: maybe}\n"))
	require.Error(t, err, "an invalid value of a known key still fails")
}
