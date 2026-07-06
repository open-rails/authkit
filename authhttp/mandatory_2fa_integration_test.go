package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	authkit "github.com/open-rails/authkit"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

func TestMFARequiredRoleHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := mandatory2FATestConfig()
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)
	require.NoError(t, srv.svc.SeedPermissionGroupContainment(ctx))
	_, err = srv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	operatorID := mustPasswordUser(t, srv, "mfa-required-operator")
	_, err = srv.svc.Enable2FA(ctx, operatorID, "email", nil)
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRole(ctx, embedded.RootPersona, "", operatorID, embedded.SubjectKindUser, "admin"))

	adminID := mustPasswordUser(t, srv, "mfa-required-admin")
	err = srv.svc.AssignGroupRole(ctx, embedded.RootPersona, "", adminID, embedded.SubjectKindUser, "admin")
	require.True(t, errors.Is(err, authkit.ErrTwoFAEnrollmentRequired), "assign without MFA = %v", err)

	_, err = srv.svc.Enable2FA(ctx, adminID, "email", nil)
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRole(ctx, embedded.RootPersona, "", adminID, embedded.SubjectKindUser, "admin"))

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
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")
	require.Contains(t, w.Body.String(), "access_token")
}

// #249 follow-up: an MFA-required role assigned while TwoFactor.Mode is
// Disabled (the assignment gate short-circuits there so bootstrap can't
// brick) leaves the holder unenrolled. If the host later re-enables 2FA
// (Mode: Optional), the refresh path must now challenge that holder to
// enroll — previously nothing did, since the only login/refresh gate was
// tied to Mode==Required for every user, not to per-role holders under
// Optional.
func TestMFARequiredRoleLoginGate_HTTPRefresh(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()

	bootstrapCfg := mandatory2FATestConfig()
	bootstrapCfg.TwoFactor = embedded.TwoFactorConfig{Mode: embedded.TwoFactorDisabled}
	bootstrapSrv, err := NewServer(newServerClient(t, bootstrapCfg, pool), WithoutRateLimiter())
	require.NoError(t, err)
	require.NoError(t, bootstrapSrv.svc.SeedPermissionGroupContainment(ctx))
	_, err = bootstrapSrv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)

	// Bootstrap: assign the MFA-required "admin" role to a never-enrolled
	// user while 2FA is fully disabled — the assignment gate is inert here.
	unenrolledID := mustPasswordUser(t, bootstrapSrv, "mfa-gate-role-disabled")
	require.NoError(t, bootstrapSrv.svc.AssignGroupRole(ctx, embedded.RootPersona, "", unenrolledID, embedded.SubjectKindUser, "admin"))

	// Still Mode=Disabled: login succeeds with no 2FA challenge at all.
	w := login(t, bootstrapSrv, "mfa-gate-role-disabled", unenrolledID)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)

	// The host re-enables 2FA (Mode: Optional). A fresh server sharing the
	// same DB state models a config-only redeploy: Mode is read fresh on
	// every request, so nothing above is mutated by the flip.
	optionalSrv, err := NewServer(newServerClient(t, mandatory2FATestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	w = serveJSON(optionalSrv, http.MethodPost, "/token", `{"grant_type":"refresh_token","refresh_token":"`+tokens.RefreshToken+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "2fa_enrollment_required")
	require.Contains(t, w.Body.String(), "access_token")
}

func mandatory2FATestConfig() embedded.Config {
	cfg := newServerTestConfig()
	cfg.RBAC = []embedded.PersonaDef{{
		Name: embedded.RootPersona,
		Roles: []embedded.RoleDef{{
			Name:        "admin",
			Permissions: []string{"root:*"},
			RequiresMFA: true,
		}},
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
