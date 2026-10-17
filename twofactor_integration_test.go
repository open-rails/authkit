package authkit_test

import (
	"context"
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

// A UV passkey is an enrollable MFA alternative even without a TOTP key
// or healthy code sender. Code-method capabilities remain accurate, and no
// code-factor availability grants a session before mandatory enrollment.
func TestNewSupportsPasskeysWithoutAnEnrollableCodeFactor(t *testing.T) {
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
		t.Cleanup(func() { _ = auth.Close(context.Background()) })
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
	t.Run("passkeys remain available without code factors", func(t *testing.T) {
		for name, edit := range map[string]func(*authkit.Config){
			"no key, no senders": nil,
			"required mode, TOTP only": func(c *authkit.Config) {
				c.TwoFactor.Mode = iam.TwoFactorRequired
				c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP}
			},
			"a key, but TOTP not offered": func(c *authkit.Config) {
				c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorEmail}
				c.TwoFactor.TOTPSecretKey = testTOTPKey
			},
		} {
			t.Run(name, func(t *testing.T) {
				auth := boot(t, config(edit), testDeps(pg.Pool))
				require.NoError(t, probe(t, auth, "authkit_two_factor"))
				require.Empty(t, auth.TwoFactorMethods())
				rec := httptest.NewRecorder()
				auth.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
				require.Equal(t, http.StatusOK, rec.Code)
				var caps struct {
					Passkeys struct {
						Login bool `json:"login"`
					} `json:"passkeys"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &caps))
				require.True(t, caps.Passkeys.Login, "mandatory enrollment can use a verified passkey")
			})
		}
		auth := boot(t, config(func(c *authkit.Config) {
			c.TwoFactor.Mode = iam.TwoFactorRequired
			c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP}
		}), testDeps(pg.Pool))
		u := authtest.NewUser(t, auth)
		w := serve(auth, http.MethodPost, "/api/v1/password/login", `{"identifier":"`+u.Email+`","password":"`+u.Password+`"}`)
		var res struct {
			Status     string        `json:"status"`
			TokenSet   *iam.TokenSet `json:"token_set"`
			Enrollment struct {
				AllowedMethods []iam.TwoFactorMethod `json:"allowed_methods"`
			} `json:"enrollment"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res), w.Body.String())
		require.Equal(t, "enrollment_required", res.Status, "the gate stays closed")
		require.Nil(t, res.TokenSet, "no session")
		require.Empty(t, res.Enrollment.AllowedMethods)
	})

	t.Run("an unknown method is refused", func(t *testing.T) {
		auth, err := authkit.New(t.Context(), config(func(c *authkit.Config) { c.TwoFactor.Methods = []iam.TwoFactorMethod{"push"} }), testDeps(pg.Pool))
		require.EqualError(t, err, `authkit: invalid TwoFactor.Methods entry "push" (want email, sms, or totp)`)
		require.Nil(t, auth)
	})

	t.Run("the key file enables TOTP", func(t *testing.T) {
		dir := t.TempDir()
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "totp.key"), []byte(hex.EncodeToString(raw)), 0o600))
		auth := boot(t, config(func(c *authkit.Config) { c.Keys.Path = dir }), testDeps(pg.Pool))
		require.NoError(t, probe(t, auth, "authkit_two_factor"))
		mode, methods := offered(t, auth)
		require.Equal(t, iam.TwoFactorOptional, mode)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorTOTP}, methods)
	})

	t.Run("dev keys generate the key, once", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keys")
		dev := config(func(c *authkit.Config) { c.Keys = authkit.KeysConfig{Path: dir, AllowEphemeralDevKeys: true} })
		_, methods := offered(t, boot(t, dev, testDeps(pg.Pool)))
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorTOTP}, methods)
		info, err := os.Stat(filepath.Join(dir, "totp.key"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		key, err := os.ReadFile(filepath.Join(dir, "totp.key"))
		require.NoError(t, err)
		boot(t, dev, testDeps(pg.Pool))
		again, err := os.ReadFile(filepath.Join(dir, "totp.key"))
		require.NoError(t, err)
		require.Equal(t, key, again, "a restart reuses it")
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
