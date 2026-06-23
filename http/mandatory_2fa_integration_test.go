package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestMFARequiredRoleHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := mandatory2FATestConfig()
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)
	require.NoError(t, srv.svc.SeedPermissionGroupContainment(ctx))
	_, err = srv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	operatorID := mustPasswordUser(t, srv, "mfa-required-operator")
	_, err = srv.svc.Enable2FA(ctx, operatorID, "email", nil)
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRole(ctx, core.RootPersona, "", operatorID, core.SubjectKindUser, "admin"))

	adminID := mustPasswordUser(t, srv, "mfa-required-admin")
	err = srv.svc.AssignGroupRole(ctx, core.RootPersona, "", adminID, core.SubjectKindUser, "admin")
	require.True(t, errors.Is(err, core.ErrTwoFAEnrollmentRequired), "assign without MFA = %v", err)

	_, err = srv.svc.Enable2FA(ctx, adminID, "email", nil)
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRole(ctx, core.RootPersona, "", adminID, core.SubjectKindUser, "admin"))

	w := login(t, srv, "mfa-required-admin", adminID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var challenge struct {
		Requires2FA bool   `json:"requires_2fa"`
		Challenge   string `json:"challenge"`
		Method      string `json:"method"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.True(t, challenge.Requires2FA)
	require.Equal(t, "email", challenge.Method)

	ordinaryID := mustPasswordUser(t, srv, "mfa-required-refresh")
	w = login(t, srv, "mfa-required-refresh", ordinaryID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	_, err = srv.svc.Enable2FA(ctx, ordinaryID, "email", nil)
	require.NoError(t, err)

	w = serveJSON(srv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")
}

func mandatory2FATestConfig() core.Config {
	cfg := newServerTestConfig()
	cfg.RBAC.Groups = []core.PersonaDef{{
		Name: core.RootPersona,
		Roles: []core.RoleDef{{
			Name:        "admin",
			Permissions: []string{"root:*"},
			RequiresMFA: true,
		}},
		Routes: core.ManagementProfile{MemberAssignment: true},
	}}
	return cfg
}

func mustPasswordUser(t *testing.T, srv *Service, prefix string) string {
	t.Helper()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := srv.svc.CreateUser(context.Background(), email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(context.Background(), `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id("Correct-password-12345")
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(context.Background(), user.ID, hash, "argon2id", nil))
	return user.ID
}

func login(t *testing.T, srv *Service, prefix, userID string) *httptest.ResponseRecorder {
	t.Helper()
	email := uniqueEmail(prefix)
	if u, err := srv.svc.AdminGetUser(context.Background(), userID); err == nil && u != nil && u.Email != nil {
		email = *u.Email
	}
	return serveJSON(srv, http.MethodPost, "/password/login", `{"login":"`+email+`","password":"Correct-password-12345"}`)
}
