package authhttp

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

func TestConfiguredPasswordPolicyIsEnforcedAndPublished(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.Password = password.Policy{MinLength: 12, MaxLength: 20}
	f := newAccountFlow(t, pg.Pool, ephemeralStore{name: "memory"}, cfg)

	caps := f.expect(http.StatusOK, f.request(http.MethodGet, "/capabilities", "", nil))
	var wire struct {
		Password map[string]any `json:"password"`
	}
	require.NoError(t, json.Unmarshal([]byte(caps.raw), &wire))
	require.Equal(t, map[string]any{"login": true, "min_length": float64(12), "max_length": float64(20)}, wire.Password)

	rejects := func(r flowResponse, code string) {
		t.Helper()
		var env struct {
			Error struct {
				Code     string         `json:"code"`
				Param    string         `json:"param"`
				Metadata map[string]any `json:"metadata"`
			} `json:"error"`
		}
		require.Equal(t, http.StatusBadRequest, r.status, r.raw)
		require.NoError(t, json.Unmarshal([]byte(r.raw), &env))
		require.Equal(t, code, env.Error.Code)
		require.Equal(t, "password", env.Error.Param)
		require.Equal(t, map[string]any{"min_length": float64(12), "max_length": float64(20)}, env.Error.Metadata)
	}
	register := func(pass string) flowResponse {
		return f.post("/register", map[string]any{"identifier": "policy@example.test", "username": "policyuser", "password": pass})
	}
	rejects(register("elevenchars"), "password_too_short")
	rejects(register(strings.Repeat("x", 21)), "password_too_long")
	// Length is counted in characters: 12 two-byte runes pass a 20-character maximum.
	pass := strings.Repeat("é", 12)
	tokens := f.expect(http.StatusAccepted, register(pass)).Tokens
	require.NotEmpty(t, tokens.AccessToken)

	change := func(next string) flowResponse {
		return f.request(http.MethodPost, "/user/password", tokens.AccessToken, map[string]any{"current_password": pass, "new_password": next})
	}
	rejects(change("short-pass"), "password_too_short")
	rejects(change(strings.Repeat("y", 21)), "password_too_long")
	rejects(f.post("/password/reset/confirm", map[string]any{"token": "unused", "new_password": "short-pass"}), "password_too_short")
	f.expect(http.StatusNoContent, change("twelve-chars"))
}
