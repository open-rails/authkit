package authhttp

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	authkit "github.com/open-rails/authkit"
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
	f := newAccountFlow(t, pg.Pool, cfg)

	caps := f.expect(http.StatusOK, f.request(http.MethodGet, "/capabilities", "", nil))
	var wire struct {
		Password map[string]any `json:"password"`
	}
	require.NoError(t, json.Unmarshal([]byte(caps.raw), &wire))
	require.Equal(t, map[string]any{"login": true, "min_length": float64(12), "max_length": float64(20),
		"require_uppercase": false, "require_lowercase": false, "require_digit": false, "require_symbol": false, "reject_common": true}, wire.Password)

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

type policyEnvelope struct {
	Error struct {
		Code     string         `json:"code"`
		Param    string         `json:"param"`
		Metadata map[string]any `json:"metadata"`
	} `json:"error"`
}

func policyError(t *testing.T, r flowResponse, code, param string) map[string]any {
	t.Helper()
	var env policyEnvelope
	require.Equal(t, http.StatusBadRequest, r.status, r.raw)
	require.NoError(t, json.Unmarshal([]byte(r.raw), &env))
	require.Equal(t, code, env.Error.Code, r.raw)
	require.Equal(t, param, env.Error.Param)
	return env.Error.Metadata
}

func TestDefaultPasswordPolicyRejectsCommonAndIdentifierPasswords(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	f := newAccountFlow(t, pg.Pool, cfg)

	caps := f.expect(http.StatusOK, f.request(http.MethodGet, "/capabilities", "", nil))
	var wire struct {
		Password map[string]any `json:"password"`
		Username map[string]any `json:"username"`
	}
	require.NoError(t, json.Unmarshal([]byte(caps.raw), &wire))
	require.Equal(t, map[string]any{"login": true, "min_length": float64(8), "max_length": float64(128),
		"require_uppercase": false, "require_lowercase": false, "require_digit": false, "require_symbol": false, "reject_common": true}, wire.Password)
	require.Equal(t, map[string]any{"min_length": float64(4), "max_length": float64(30), "pattern": authkit.UsernamePattern}, wire.Username)

	register := func(email, username, pass string) flowResponse {
		return f.post("/register", map[string]any{"identifier": email, "username": username, "password": pass})
	}
	require.Nil(t, policyError(t, register("common@example.test", "commonuser", "QwertyUIOP"), "password_too_common", "password"))
	for _, common := range []string{"password123", "Password1!", "qwerty12345", "iloveyou123"} {
		policyError(t, register("common@example.test", "commonuser", common), "password_too_common", "password")
	}
	policyError(t, register("common@example.test", "commonuser", "my-commonuser-pass"), "password_contains_identifier", "password")
	policyError(t, register("mailbox.owner@example.test", "someoneelse", "xx-MAILBOX.OWNER-xx"), "password_contains_identifier", "password")
	tokens := f.expect(http.StatusAccepted, register("common@example.test", "commonuser", "violet-harbor-lantern")).Tokens

	change := func(next string) flowResponse {
		return f.request(http.MethodPost, "/user/password", tokens.AccessToken, map[string]any{"current_password": "violet-harbor-lantern", "new_password": next})
	}
	policyError(t, change("iloveyou1"), "password_too_common", "password")
	policyError(t, change("renamed-COMMONUSER-1"), "password_contains_identifier", "password")
}

func TestHostPasswordCompositionAndUsernameBounds(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.Password = password.Policy{RequireSymbol: true, RequireDigit: true, AllowCommon: true}
	cfg.Username = authkit.UsernamePolicy{MinLength: 6, MaxLength: 12}
	f := newAccountFlow(t, pg.Pool, cfg)

	caps := f.expect(http.StatusOK, f.request(http.MethodGet, "/capabilities", "", nil))
	var wire struct {
		Password map[string]any `json:"password"`
		Username map[string]any `json:"username"`
	}
	require.NoError(t, json.Unmarshal([]byte(caps.raw), &wire))
	require.Equal(t, true, wire.Password["require_symbol"])
	require.Equal(t, true, wire.Password["require_digit"])
	require.Equal(t, false, wire.Password["reject_common"])
	require.Equal(t, float64(6), wire.Username["min_length"])
	require.Equal(t, float64(12), wire.Username["max_length"])

	register := func(username, pass string) flowResponse {
		return f.post("/register", map[string]any{"identifier": "compose@example.test", "username": username, "password": pass})
	}
	missing := policyError(t, register("composer", "lettersonly"), "password_requirements_unmet", "password")
	require.Equal(t, []any{"digit", "symbol"}, missing["missing"])
	require.Equal(t, map[string]any{"min_length": float64(6), "max_length": float64(12)}, policyError(t, register("compo", "abc-12345"), "username_too_short", "username"))
	require.Equal(t, map[string]any{"min_length": float64(6), "max_length": float64(12)}, policyError(t, register("composer_long", "abc-12345"), "username_too_long", "username"))
	policyError(t, register("1composer", "abc-12345"), "username_must_start_with_letter", "username")
	tokens := f.expect(http.StatusAccepted, register("composer", "password1!")).Tokens

	rename := f.request(http.MethodPatch, "/user/username", tokens.AccessToken, map[string]any{"username": "abc"})
	require.Equal(t, map[string]any{"min_length": float64(6), "max_length": float64(12)}, policyError(t, rename, "username_too_short", "username"))
}
