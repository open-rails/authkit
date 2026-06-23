package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestMandatory2FARootRolePolicyHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := mandatory2FATestConfig()
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)
	require.NoError(t, srv.Core().SeedPermissionGroupContainment(ctx))
	_, err = srv.Core().EnsureRootGroup(ctx)
	require.NoError(t, err)
	require.NoError(t, srv.Core().AssignGroupRole(ctx, core.RootType, "", mustPasswordUser(t, srv, "mandatory-admin"), core.SubjectKindUser, "admin"))

	adminID := mustPasswordUser(t, srv, "mandatory-admin-login")
	require.NoError(t, srv.Core().AssignGroupRole(ctx, core.RootType, "", adminID, core.SubjectKindUser, "admin"))

	w := login(t, srv, "mandatory-admin-login", adminID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Error                 string   `json:"error"`
		Requires2FAEnrollment bool     `json:"requires_2fa_enrollment"`
		AllowedMethods        []string `json:"allowed_methods"`
		AccessToken           string   `json:"access_token"`
		RefreshToken          string   `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	require.Equal(t, "2fa_enrollment_required", enrollment.Error)
	require.True(t, enrollment.Requires2FAEnrollment)
	require.ElementsMatch(t, []string{"email", "sms", "totp"}, enrollment.AllowedMethods)
	require.NotEmpty(t, enrollment.AccessToken)
	require.Empty(t, enrollment.RefreshToken)

	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, enrollment.AccessToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, enrollment.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var setup struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &setup))
	require.NotEmpty(t, setup.Secret)

	code := testTOTPCode(t, setup.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, enrollment.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = login(t, srv, "mandatory-admin-login", adminID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var challenge struct {
		Requires2FA bool   `json:"requires_2fa"`
		Challenge   string `json:"challenge"`
		Method      string `json:"method"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.True(t, challenge.Requires2FA)
	require.Equal(t, "totp", challenge.Method)

	loginCode := testTOTPCode(t, setup.Secret, time.Now().Unix()/30+1)
	w = serveJSON(srv, http.MethodPost, "/2fa/verify", `{"user_id":"`+adminID+`","challenge":"`+challenge.Challenge+`","code":"`+loginCode+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.Equal(t, "urn:authkit:loa:2", claims["acr"])
	require.ElementsMatch(t, []any{"pwd", "otp", "mfa"}, claims["amr"])

	ordinaryID := mustPasswordUser(t, srv, "mandatory-refresh")
	w = login(t, srv, "mandatory-refresh", ordinaryID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	require.NoError(t, srv.Core().AssignGroupRole(ctx, core.RootType, "", ordinaryID, core.SubjectKindUser, "admin"))

	w = serveJSON(srv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")
}

func mandatory2FATestConfig() core.Config {
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	cfg.TwoFactor.Mandatory = []core.Mandatory2FAPolicy{{
		GroupType: core.RootType,
		Roles:     []string{"admin"},
	}}
	cfg.RBAC.Groups = []core.GroupTypeDef{{
		Name: core.RootType,
		Roles: []core.RoleDef{{
			Name:        "admin",
			Permissions: []string{"root:*"},
		}},
		Routes: core.ManagementProfile{MemberAssignment: true},
	}}
	return cfg
}

func mustPasswordUser(t *testing.T, srv *Service, prefix string) string {
	t.Helper()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := srv.Core().CreateUser(context.Background(), email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.Core().Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id("Correct-password-12345")
	require.NoError(t, err)
	require.NoError(t, srv.Core().UpsertPasswordHash(context.Background(), user.ID, hash, "argon2id", nil))
	return user.ID
}

func login(t *testing.T, srv *Service, prefix, userID string) *httptest.ResponseRecorder {
	t.Helper()
	email := uniqueEmail(prefix)
	if u, err := srv.Core().AdminGetUser(context.Background(), userID); err == nil && u != nil && u.Email != nil {
		email = *u.Email
	}
	return serveJSON(srv, http.MethodPost, "/password/login", `{"login":"`+email+`","password":"Correct-password-12345"}`)
}
