package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/stretchr/testify/require"
)

// New copies the engine configuration into the HTTP surface it builds: the
// public capabilities route reports the configured policy, served through
// Mount at the configured prefix.
func TestNewServesConfiguredCapabilities(t *testing.T) {
	signer := testkeys.RSA("capabilities")
	auth, err := authkit.New(context.Background(), authkit.Config{
		Token: authkit.TokenConfig{Issuer: "https://capabilities.test", IssuedAudiences: []string{"app"}},
		Registration: authkit.RegistrationConfig{
			NativeUserMode:    iam.RegistrationModeInviteOnly,
			Verification:      iam.RegistrationVerificationOptional,
			PasswordlessLogin: true,
		},
		Username: authkit.UsernameConfig{MinLength: 6, MaxLength: 20, Renames: true, RenameInterval: time.Hour,
			FormerNames: authkit.FormerNamesConfig{Mode: authkit.FormerNamesForever}},
		Password:      &authkit.PasswordPolicy{MinLength: 12, RequireDigit: true},
		SolanaNetwork: "devnet",
		Languages:     authkit.LanguageConfig{Supported: []string{"en", "es"}},
		HTTP:          &authkit.HTTPConfig{DirectPeerIP: true, APIPath: "/auth"},
	}, authkit.Deps{Postgres: testdb.Pool(t), KeySource: testkeys.Source(signer)})
	require.NoError(t, err)
	t.Cleanup(auth.Close)

	mux := http.NewServeMux()
	require.NoError(t, auth.Mount(mux))
	require.Contains(t, patterns(auth), "GET /auth/capabilities")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var caps struct {
		Registration struct {
			Mode                string `json:"mode"`
			InviteTokenRequired bool   `json:"invite_token_required"`
		} `json:"registration"`
		Username struct {
			MinLength             int  `json:"min_length"`
			MaxLength             int  `json:"max_length"`
			Renames               bool `json:"renames"`
			RenameIntervalSeconds int  `json:"rename_interval_seconds"`
			FormerNames           struct {
				Mode string `json:"former_name_retention_mode"`
			} `json:"former_names"`
		} `json:"username"`
		Password struct {
			MinLength    int  `json:"min_length"`
			MaxLength    int  `json:"max_length"`
			RequireDigit bool `json:"require_digit"`
			AllowCommon  bool `json:"allow_common"`
		} `json:"password"`
		Passwordless struct {
			Enabled bool `json:"enabled"`
		} `json:"passwordless"`
		Solana struct {
			Login bool `json:"login"`
		} `json:"solana"`
		Verification struct {
			Registration string `json:"registration"`
		} `json:"verification"`
		Channels  map[string]bool `json:"channels"`
		Languages []string        `json:"languages"`
		Paths     map[string]any  `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &caps))
	require.Equal(t, "invite_only", caps.Registration.Mode)
	require.True(t, caps.Registration.InviteTokenRequired)
	require.Equal(t, 6, caps.Username.MinLength)
	require.Equal(t, 20, caps.Username.MaxLength)
	require.True(t, caps.Username.Renames)
	require.Equal(t, 3600, caps.Username.RenameIntervalSeconds)
	require.Equal(t, "forever", caps.Username.FormerNames.Mode)
	require.Equal(t, 12, caps.Password.MinLength)
	require.Equal(t, 128, caps.Password.MaxLength)
	require.True(t, caps.Password.RequireDigit)
	require.False(t, caps.Password.AllowCommon, "a policy set for its lengths keeps the common-password blocklist")
	require.True(t, caps.Passwordless.Enabled)
	require.True(t, caps.Solana.Login)
	require.Equal(t, "optional", caps.Verification.Registration)
	require.Equal(t, []string{"en", "es"}, caps.Languages)
	require.Equal(t, map[string]bool{"email": false, "sms": false}, caps.Channels, "no senders, no channels")
	require.Equal(t, map[string]any{"api": "/auth", "jwks": iam.JWKSPath, "oidc": nil}, caps.Paths, "a root issuer keeps root anchors; no providers, no OIDC")

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	require.Equal(t, http.StatusNotFound, rec.Code, "the API is anchored at the configured prefix only")
}
