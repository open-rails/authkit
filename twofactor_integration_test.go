package authkit_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// New refuses a deployment where a role needs MFA but no second factor can be
// enrolled (no totp.key, no email or SMS sender), naming the roles and the
// fixes; it boots once one method works, or with 2FA disabled. The Client and
// GET /capabilities report the methods a user can enroll.
func TestNewRequiresAnEnrollableSecondFactor(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	noKey := t.TempDir()
	rbac := authkit.NewRoles()
	org := rbac.Persona("org")
	org.RequireMFA(org.Members.Manage)
	org.Role("moderator", org.Members.Read)
	org.Role("admin", org.Members.Manage)
	config := func(edit func(*authkit.Config)) authkit.Config {
		cfg := testConfig(t)
		cfg.Keys.Path = noKey
		cfg.TwoFactor.TOTPSecretKey = nil
		cfg.Roles = rbac
		cfg.HTTP = &authkit.HTTPConfig{DirectPeerIP: true}
		if edit != nil {
			edit(&cfg)
		}
		return cfg
	}
	boot := func(t *testing.T, cfg authkit.Config, deps authkit.Deps) *authkit.Client {
		t.Helper()
		auth, err := authkit.New(t.Context(), cfg, deps)
		require.NoError(t, err)
		t.Cleanup(auth.Close)
		return auth
	}
	// offered is what GET /capabilities reports, which must match the Client.
	offered := func(t *testing.T, auth *authkit.Client) (iam.TwoFactorMode, []iam.TwoFactorMethod) {
		t.Helper()
		rec := httptest.NewRecorder()
		auth.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var caps struct {
			TwoFactor struct {
				Mode    iam.TwoFactorMode     `json:"mode"`
				Methods []iam.TwoFactorMethod `json:"methods"`
			} `json:"two_factor"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &caps))
		require.Equal(t, auth.TwoFactorMethods(), caps.TwoFactor.Methods)
		return caps.TwoFactor.Mode, caps.TwoFactor.Methods
	}
	keyAt := filepath.Join(noKey, "totp.key")

	t.Run("refused without an enrollable factor", func(t *testing.T) {
		for name, tc := range map[string]struct {
			edit func(*authkit.Config)
			err  string
		}{
			"no key, no senders": {
				err: "authkit: roles org:admin, org:owner, root:owner need MFA, but no second factor can be enrolled: " +
					"put a 16, 24 or 32-byte key at " + keyAt + " (or set TwoFactor.TOTPSecretKey), or set Deps.Email, or set Deps.SMS, " +
					"or set TwoFactor.Mode to disabled",
			},
			"required mode, TOTP only": {
				edit: func(c *authkit.Config) {
					c.TwoFactor.Mode = iam.TwoFactorRequired
					c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP}
				},
				err: "authkit: TwoFactor.Mode is required, so every account needs MFA, but no second factor can be enrolled: " +
					"put a 16, 24 or 32-byte key at " + keyAt + " (or set TwoFactor.TOTPSecretKey), or set TwoFactor.Mode to disabled",
			},
			"a key, but TOTP not offered": {
				edit: func(c *authkit.Config) {
					c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorEmail}
					c.TwoFactor.TOTPSecretKey = testTOTPKey
				},
				err: "authkit: roles org:admin, org:owner, root:owner need MFA, but no second factor can be enrolled: " +
					"set Deps.Email, or set TwoFactor.Mode to disabled",
			},
			"an unknown method": {
				edit: func(c *authkit.Config) { c.TwoFactor.Methods = []iam.TwoFactorMethod{"push"} },
				err:  `authkit: invalid TwoFactor.Methods entry "push" (want email, sms, or totp)`,
			},
		} {
			t.Run(name, func(t *testing.T) {
				auth, err := authkit.New(t.Context(), config(tc.edit), testDeps(pg.Pool))
				require.EqualError(t, err, tc.err)
				require.Nil(t, auth)
			})
		}
	})

	t.Run("the key file enables TOTP", func(t *testing.T) {
		dir := t.TempDir()
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "totp.key"), []byte(hex.EncodeToString(raw)), 0o600))
		auth := boot(t, config(func(c *authkit.Config) { c.Keys.Path = dir }), testDeps(pg.Pool))
		mode, methods := offered(t, auth)
		require.Equal(t, iam.TwoFactorOptional, mode)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorTOTP}, methods)
	})

	t.Run("another method leaves a missing key a warning", func(t *testing.T) {
		deps := testDeps(pg.Pool)
		outbox := &authtest.Outbox{}
		deps.Email, deps.SMS = outbox.Email(), outbox.SMS()
		auth := boot(t, config(nil), deps)
		_, methods := offered(t, auth)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorSMS}, methods)
	})

	t.Run("disabled needs none", func(t *testing.T) {
		auth := boot(t, config(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }), testDeps(pg.Pool))
		mode, methods := offered(t, auth)
		require.Equal(t, iam.TwoFactorDisabled, mode)
		require.Empty(t, methods)
		require.NotNil(t, methods, "an empty list, never null")
	})

	t.Run("a verify-only engine signs no one in", func(t *testing.T) {
		cfg := config(func(c *authkit.Config) { c.Keys.VerifyOnly, c.HTTP = true, nil })
		auth := boot(t, cfg, authkit.Deps{Postgres: pg.Pool})
		require.Empty(t, auth.TwoFactorMethods())
	})
}
