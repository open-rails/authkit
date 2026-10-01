package apitest_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// An unknown bootstrap manifest key is logged as a warning naming its path
// and ignored; an invalid value of a known key still fails the parse. The
// parse needs no Client, so a tool can check a file before it connects. It
// replaces the process logger, so it never runs in parallel.
func TestBootstrapManifestIgnoresUnknownKeys(t *testing.T) {
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	manifest, err := authkit.ParseBootstrapManifestYAML([]byte(`version: 2
users:
 - username: unknown-keys
   email: unknown-keys@example.test
   email_verified: true
   nickname: uk
   public_metadata: {anything: {goes: here}}
   metadata: {legacy: true}
   password: {plaintext: bootstrap-password-1, rotate: true}
`))
	require.NoError(t, err)
	require.Contains(t, logs.String(), "level=WARN")
	for _, path := range []string{"version", "users[0].nickname", "users[0].metadata", "users[0].password.rotate"} {
		require.Contains(t, logs.String(), `ignoring unknown key" path=`+path+"\n")
	}
	require.NotContains(t, logs.String(), "path=users[0].public_metadata", "public metadata is free-form")
	require.NotContains(t, logs.String(), "path=users[0].email\n")

	auth, _ := authtest.New(t)
	ctx := t.Context()
	result, err := auth.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.UsersCreated)
	u, err := auth.User(ctx, iam.UserByUsername("unknown-keys"))
	require.NoError(t, err)
	require.NotNil(t, u.Email)
	require.Equal(t, "unknown-keys@example.test", *u.Email)
	require.Equal(t, map[string]any{"anything": map[string]any{"goes": "here"}}, u.PublicMetadata)

	_, err = authkit.ParseBootstrapManifestYAML([]byte("users:\n - {username: bad, email_verified: maybe}\n"))
	require.Error(t, err, "an invalid value of a known key still fails")
}

// The Client-less parse checks structure only: a root_role of another persona
// fails it, while a root role the catalog does not declare and a password the
// policy refuses parse, and Apply refuses them against the Client's Config.
func TestBootstrapManifestParseIsStructural(t *testing.T) {
	_, err := authkit.ParseBootstrapManifestYAML([]byte("users:\n - {username: channel-mod, root_role: channel:moderator}\n"))
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable, "a root_role must be a root role")

	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	ctx := t.Context()
	undeclared, err := authkit.ParseBootstrapManifestYAML([]byte("users:\n - {username: ghost-admin, root_role: root:ghost}\n"))
	require.NoError(t, err)
	_, err = auth.ApplyBootstrapManifest(ctx, undeclared, iam.BootstrapOptions{DryRun: true})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)

	weak, err := authkit.ParseBootstrapManifestYAML([]byte("users:\n - {username: weak-seed, password: {plaintext: short}}\n"))
	require.NoError(t, err)
	_, err = auth.ApplyBootstrapManifest(ctx, weak, iam.BootstrapOptions{DryRun: true})
	requireIAMCode(t, err, "password_too_short")
}
