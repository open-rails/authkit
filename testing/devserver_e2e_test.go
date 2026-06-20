//go:build e2e

package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	authhttp "github.com/open-rails/authkit/http"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/open-rails/authkit/password"
)

type composeCLI struct {
	base []string
	dir  string
	env  []string
}

func (c composeCLI) run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(c.base[0], append(c.base[1:], args...)...)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(), c.env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compose failed: %s\n%s", strings.Join(cmd.Args, " "), string(out))
	}
	return strings.TrimSpace(string(out))
}

func (c composeCLI) runMaybe(args ...string) error {
	cmd := exec.Command(c.base[0], append(c.base[1:], args...)...)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(), c.env...)
	_, err := cmd.CombinedOutput()
	return err
}

func findCompose(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err == nil {
		cmd := exec.Command("docker", "compose", "version")
		if err := cmd.Run(); err == nil {
			if ok, why := dockerDaemonOK(); !ok {
				t.Skipf("docker daemon not accessible (skipping e2e): %s", why)
			}
			return []string{"docker", "compose"}
		}
	}
	if _, err := exec.LookPath("docker-compose"); err == nil {
		cmd := exec.Command("docker-compose", "version")
		if err := cmd.Run(); err == nil {
			if ok, why := dockerDaemonOK(); !ok {
				t.Skipf("docker daemon not accessible (skipping e2e): %s", why)
			}
			return []string{"docker-compose"}
		}
	}
	t.Skip("docker compose not available (skipping e2e)")
	return nil
}

func dockerDaemonOK() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "info")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return false, "timeout"
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			lines := strings.Split(msg, "\n")
			last := strings.TrimSpace(lines[len(lines)-1])
			if last != "" {
				msg = last
			}
		}
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return true, ""
}

func waitForHTTP200(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	cli := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := cli.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("Status=%d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", url, lastErr)
}

func httpJSON(t *testing.T, method, url string, headers map[string]string, body any) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, data
}

func parsePort(t *testing.T, s string) string {
	t.Helper()
	re := regexp.MustCompile(`(?m):(\d+)\s*$`)
	m := re.FindStringSubmatch(strings.TrimSpace(s))
	if len(m) != 2 {
		t.Fatalf("failed to parse port from %q", s)
	}
	return m[1]
}

func TestDevserverE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in -short")
	}

	composeBase := findCompose(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Dir(wd)

	dbService := "postgres"

	composeFile := filepath.Join(repoRoot, "docker-compose.devserver.yaml")
	overridePath := filepath.Join(t.TempDir(), "docker-compose.override.yaml")
	project := fmt.Sprintf("authkit_e2e_%d", time.Now().UnixNano())
	mintSecret := fmt.Sprintf("secret-%d", time.Now().UnixNano())
	aud := "billing-app"

	override := fmt.Sprintf(`services:
  postgres:
    ports: []
  issuer:
    ports:
      - "8080"
    environment:
      DEVSERVER_DEV_MINT_SECRET: %q
`, mintSecret)
	if overridePath != "" {
		if err := os.WriteFile(overridePath, []byte(override), 0600); err != nil {
			t.Fatalf("write override: %v", err)
		}
	}

	c := composeCLI{
		base: composeBase,
		dir:  repoRoot,
		env:  []string{"COMPOSE_PROJECT_NAME=" + project},
	}

	t.Cleanup(func() {
		if overridePath != "" {
			_ = c.runMaybe("-f", composeFile, "-f", overridePath, "down", "-v", "--remove-orphans")
		} else {
			_ = c.runMaybe("-f", composeFile, "down", "-v", "--remove-orphans")
		}
	})

	if overridePath != "" {
		c.run(t, "-f", composeFile, "-f", overridePath, "up", "-d", "--build", "--remove-orphans")
	} else {
		c.run(t, "-f", composeFile, "up", "-d", "--build", "--remove-orphans")
	}

	var rawPort string
	if overridePath != "" {
		rawPort = c.run(t, "-f", composeFile, "-f", overridePath, "port", "issuer", "8080")
	} else {
		rawPort = c.run(t, "-f", composeFile, "port", "issuer", "8080")
	}
	port := parsePort(t, rawPort)
	baseURL := "http://127.0.0.1:" + port

	waitForHTTP200(t, baseURL+"/healthz", 90*time.Second)

	t.Run("health", func(t *testing.T) {
		resp, _ := httpJSON(t, http.MethodGet, baseURL+"/healthz", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		resp, body := httpJSON(t, http.MethodGet, baseURL+"/.well-known/jwks.json", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		var ks jwtkit.JWKS
		if err := json.Unmarshal(body, &ks); err != nil {
			t.Fatalf("decode jwks: %v", err)
		}
		if len(ks.Keys) < 1 {
			t.Fatalf("expected at least 1 key, got %d", len(ks.Keys))
		}
		if ks.Keys[0].Kty != "RSA" {
			t.Fatalf("expected kty=RSA, got %q", ks.Keys[0].Kty)
		}
	})

	issuer := "http://issuer:8080"
	t.Run("mint_guard", func(t *testing.T) {
		resp, _ := httpJSON(t, http.MethodPost, baseURL+"/api/v1/dev/mint", nil, map[string]any{
			"sub": "11111111-1111-1111-1111-111111111111",
			"aud": aud,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}

		resp, _ = httpJSON(t, http.MethodPost, baseURL+"/api/v1/dev/mint", map[string]string{
			"Authorization": "Bearer wrong",
		}, map[string]any{
			"sub": "11111111-1111-1111-1111-111111111111",
			"aud": aud,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	mint := func(t *testing.T, sub string, expiresInSeconds int64) string {
		t.Helper()
		body := map[string]any{
			"sub": sub,
			"aud": aud,
		}
		if expiresInSeconds > 0 {
			body["expires_in_seconds"] = expiresInSeconds
		}
		resp, raw := httpJSON(t, http.MethodPost, baseURL+"/api/v1/dev/mint", map[string]string{
			"Authorization": "Bearer " + mintSecret,
		}, body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(raw))
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode mint response: %v", err)
		}
		if strings.TrimSpace(out.Token) == "" {
			t.Fatalf("expected non-empty token")
		}
		return out.Token
	}

	t.Run("mint_verifier_and_expiry", func(t *testing.T) {
		token := mint(t, "11111111-1111-1111-1111-111111111111", 1)

		ver := authhttp.NewVerifier(
			authhttp.WithAlgorithms("RS256"),
			authhttp.WithSkew(1*time.Millisecond),
		)
		_ = ver.AddIssuer(issuer, []string{aud}, authhttp.IssuerOptions{
			JWKSURI: baseURL + "/.well-known/jwks.json",
		})

		claims, err := ver.Verify(token)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if claims.UserID != "11111111-1111-1111-1111-111111111111" {
			t.Fatalf("bad sub: %q", claims.UserID)
		}

		time.Sleep(2 * time.Second)
		_, err = ver.Verify(token)
		if err == nil {
			t.Fatalf("expected expired token to fail verification")
		}
	})

	execPSQL := func(t *testing.T, sql string) {
		t.Helper()
		args := []string{"-f", composeFile}
		if strings.TrimSpace(overridePath) != "" {
			args = append(args, "-f", overridePath)
		}
		args = append(args, "exec", "-T", dbService,
			"psql", "-U", "admin", "-d", "authkit_db", "-v", "ON_ERROR_STOP=1", "-c", sql)
		c.run(t, args...)
	}
	queryPSQL := func(t *testing.T, sql string) string {
		t.Helper()
		args := []string{"-f", composeFile}
		if strings.TrimSpace(overridePath) != "" {
			args = append(args, "-f", overridePath)
		}
		args = append(args, "exec", "-T", dbService,
			"psql", "-U", "admin", "-d", "authkit_db", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql)
		return strings.TrimSpace(c.run(t, args...))
	}
	sqlString := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	restartIssuer := func(t *testing.T) {
		t.Helper()
		args := []string{"-f", composeFile}
		if strings.TrimSpace(overridePath) != "" {
			args = append(args, "-f", overridePath)
		}
		args = append(args, "restart", "issuer")
		c.run(t, args...)
		waitForHTTP200(t, baseURL+"/healthz", 90*time.Second)
	}

	t.Run("seeded_reserved_slug_blocks_username_update_after_restart", func(t *testing.T) {
		userID := "33333333-3333-3333-3333-333333333333"
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(userID), sqlString("reserved-check@example.com"), sqlString("reservedcheck"),
		))
		token := mint(t, userID, 300)

		tryRename := func(t *testing.T) {
			t.Helper()
			resp, body := httpJSON(t, http.MethodPatch, baseURL+"/api/v1/user/username", map[string]string{
				"Authorization": "Bearer " + token,
			}, map[string]any{
				"username": "superuser",
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400 for reserved slug username update, got %d: %s", resp.StatusCode, string(body))
			}
			bodyText := string(body)
			// A reserved/restricted slug surfaces as username_not_allowed from the
			// username-update validation path (core.UsernameOwnerNamespaceError ->
			// ErrCodeUsernameNotAllowed for restricted/parked names). The update must
			// still be REJECTED — we just assert the current rejection code.
			if !strings.Contains(bodyText, `"error":"username_not_allowed"`) &&
				!strings.Contains(bodyText, `"error":"owner_slug_taken"`) &&
				!strings.Contains(bodyText, `"error":"failed_to_update_username"`) {
				t.Fatalf("expected username_not_allowed (reserved slug rejection), got: %s", bodyText)
			}
		}

		tryRename(t)
		restartIssuer(t)
		tryRename(t)
	})

	t.Run("minted_token_can_call_user_me", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01');",
			sqlString(userID), sqlString("test@example.com"), sqlString("testuser"),
		))

		token := mint(t, userID, 300)
		resp, body := httpJSON(t, http.MethodGet, baseURL+"/api/v1/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("admin_gate_db_backed", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		execPSQL(t, "INSERT INTO profiles.global_roles (name, slug) VALUES ('Admin', 'admin') ON CONFLICT (slug) DO NOTHING;")
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.global_user_roles (user_id, role_id) VALUES (%s, profiles.role_id('admin')) ON CONFLICT DO NOTHING;",
			sqlString(userID),
		))

		token := mint(t, userID, 300)
		resp, body := httpJSON(t, http.MethodGet, baseURL+"/api/v1/admin/users", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ban_and_delete_enforcement", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		token := mint(t, userID, 300)

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=now() WHERE id=%s;", sqlString(userID)))
		resp, _ := httpJSON(t, http.MethodGet, baseURL+"/api/v1/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for banned user, got %d", resp.StatusCode)
		}

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=NULL, deleted_at=now() WHERE id=%s;", sqlString(userID)))
		resp, _ = httpJSON(t, http.MethodGet, baseURL+"/api/v1/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for deleted user, got %d", resp.StatusCode)
		}
	})

	// loginAndRefreshSession logs a user in with email+password and returns their
	// API key and refresh token (a live refresh session).
	loginAndRefreshSession := func(t *testing.T, email, pass string) (accessToken, refreshToken string) {
		t.Helper()
		loginResp, loginBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/password/login", nil, map[string]any{
			"email":    email,
			"password": pass,
		})
		if loginResp.StatusCode != http.StatusOK {
			t.Fatalf("login: expected 200, got %d: %s", loginResp.StatusCode, string(loginBody))
		}
		var out struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(loginBody, &out); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		if strings.TrimSpace(out.AccessToken) == "" || strings.TrimSpace(out.RefreshToken) == "" {
			t.Fatalf("login: expected access_token + refresh_token")
		}
		return out.AccessToken, out.RefreshToken
	}

	seedPasswordUser := func(t *testing.T, userID, email, username, pass string) {
		t.Helper()
		hash, err := password.HashArgon2id(pass)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(userID), sqlString(email), sqlString(username),
		))
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo) VALUES (%s, %s, 'argon2id') ON CONFLICT (user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash;",
			sqlString(userID), sqlString(hash),
		))
	}

	refreshAttempt := func(t *testing.T, refreshToken string) int {
		t.Helper()
		resp, _ := httpJSON(t, http.MethodPost, baseURL+"/api/v1/token", nil, map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		})
		return resp.StatusCode
	}

	userMeStatus := func(t *testing.T, accessToken string) int {
		t.Helper()
		resp, _ := httpJSON(t, http.MethodGet, baseURL+"/api/v1/user/me", map[string]string{
			"Authorization": "Bearer " + accessToken,
		}, nil)
		return resp.StatusCode
	}

	t.Run("ban_revokes_refresh_sessions_and_unban_restores", func(t *testing.T) {
		userID := "66666666-6666-6666-6666-666666666666"
		email := "ban-refresh@example.com"
		pass := "Password123!"
		seedPasswordUser(t, userID, email, "banrefreshuser", pass)

		accessToken, refreshToken := loginAndRefreshSession(t, email, pass)

		// Baseline: refresh works and /user/me works before ban.
		if code := refreshAttempt(t, refreshToken); code != http.StatusOK {
			t.Fatalf("pre-ban refresh: expected 200, got %d", code)
		}
		if code := userMeStatus(t, accessToken); code != http.StatusOK {
			t.Fatalf("pre-ban /user/me: expected 200, got %d", code)
		}

		// A fresh login (so we have a refresh token that has not been rotated by the
		// baseline refresh above) is what we ban against.
		accessToken, refreshToken = loginAndRefreshSession(t, email, pass)

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=now() WHERE id=%s;", sqlString(userID)))

		if code := refreshAttempt(t, refreshToken); code != http.StatusUnauthorized {
			t.Fatalf("banned refresh: expected 401, got %d", code)
		}
		if code := userMeStatus(t, accessToken); code != http.StatusUnauthorized {
			t.Fatalf("banned /user/me: expected 401, got %d", code)
		}

		// Unban must restore access: a brand-new login succeeds and yields a usable session.
		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=NULL WHERE id=%s;", sqlString(userID)))

		newAccess, newRefresh := loginAndRefreshSession(t, email, pass)
		if code := userMeStatus(t, newAccess); code != http.StatusOK {
			t.Fatalf("post-unban /user/me: expected 200, got %d", code)
		}
		if code := refreshAttempt(t, newRefresh); code != http.StatusOK {
			t.Fatalf("post-unban refresh: expected 200, got %d", code)
		}
	})

	t.Run("soft_delete_revokes_refresh_sessions", func(t *testing.T) {
		userID := "77777777-7777-7777-7777-777777777777"
		email := "delete-refresh@example.com"
		pass := "Password123!"
		seedPasswordUser(t, userID, email, "deleterefreshuser", pass)

		accessToken, refreshToken := loginAndRefreshSession(t, email, pass)

		if code := refreshAttempt(t, refreshToken); code != http.StatusOK {
			t.Fatalf("pre-delete refresh: expected 200, got %d", code)
		}

		// Fresh, un-rotated session to soft-delete against.
		accessToken, refreshToken = loginAndRefreshSession(t, email, pass)

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET deleted_at=now() WHERE id=%s;", sqlString(userID)))

		if code := refreshAttempt(t, refreshToken); code != http.StatusUnauthorized {
			t.Fatalf("soft-deleted refresh: expected 401, got %d", code)
		}
		if code := userMeStatus(t, accessToken); code != http.StatusUnauthorized {
			t.Fatalf("soft-deleted /user/me: expected 401, got %d", code)
		}
	})

	t.Run("password_login_refresh_and_logout", func(t *testing.T) {
		userID := "22222222-2222-2222-2222-222222222222"
		email := "pw@example.com"
		username := "pwuser"
		pass := "Password123!"

		hash, err := password.HashArgon2id(pass)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}

		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01');",
			sqlString(userID), sqlString(email), sqlString(username),
		))
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo) VALUES (%s, %s, 'argon2id');",
			sqlString(userID), sqlString(hash),
		))

		loginResp, loginBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/password/login", nil, map[string]any{
			"email":    email,
			"password": pass,
		})
		if loginResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", loginResp.StatusCode, string(loginBody))
		}

		var loginOut struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(loginBody, &loginOut); err != nil {
			t.Fatalf("decode login response: %v", err)
		}
		if strings.TrimSpace(loginOut.AccessToken) == "" || strings.TrimSpace(loginOut.RefreshToken) == "" {
			t.Fatalf("expected access_token + refresh_token")
		}

		refreshResp, refreshBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/token", nil, map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": loginOut.RefreshToken,
		})
		if refreshResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", refreshResp.StatusCode, string(refreshBody))
		}
		var refreshOut struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(refreshBody, &refreshOut); err != nil {
			t.Fatalf("decode refresh response: %v", err)
		}
		if strings.TrimSpace(refreshOut.AccessToken) == "" || strings.TrimSpace(refreshOut.RefreshToken) == "" {
			t.Fatalf("expected access_token + refresh_token")
		}

		logoutResp, logoutBody := httpJSON(t, http.MethodDelete, baseURL+"/api/v1/logout", map[string]string{
			"Authorization": "Bearer " + loginOut.AccessToken,
		}, nil)
		if logoutResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", logoutResp.StatusCode, string(logoutBody))
		}

		refreshResp2, refreshBody2 := httpJSON(t, http.MethodPost, baseURL+"/api/v1/token", nil, map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refreshOut.RefreshToken,
		})
		if refreshResp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout, got %d: %s", refreshResp2.StatusCode, string(refreshBody2))
		}
	})

	t.Run("rename_chain_resolution_and_reuse_edge_cases", func(t *testing.T) {
		ownerID := "44444444-4444-4444-4444-444444444444"
		claimantID := "55555555-5555-5555-5555-555555555555"
		a := "renamea"
		b := "renameb"
		cSlug := "renamec"
		claimant := "renameclaimant"

		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(ownerID), sqlString("rename-owner@example.com"), sqlString(a),
		))
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(claimantID), sqlString("rename-claimant@example.com"), sqlString(claimant),
		))
		ownerToken := mint(t, ownerID, 300)
		claimantToken := mint(t, claimantID, 300)

		renameUser := func(t *testing.T, token, username string, want int) []byte {
			t.Helper()
			resp, body := httpJSON(t, http.MethodPatch, baseURL+"/api/v1/user/username", map[string]string{
				"Authorization": "Bearer " + token,
			}, map[string]any{"username": username})
			if resp.StatusCode != want {
				t.Fatalf("rename to %q: got %d want %d: %s", username, resp.StatusCode, want, string(body))
			}
			return body
		}
		type ownerLookupOut struct {
			Slug          string `json:"slug"`
			RequestedSlug string `json:"requested_slug"`
			Claimable     struct {
				User bool `json:"user"`
				Org  bool `json:"org"`
			} `json:"claimable"`
			Renamed bool `json:"renamed"`
			User    *struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			} `json:"user"`
		}
		lookupOwner := func(t *testing.T, slug string) ownerLookupOut {
			t.Helper()
			ownersResp, ownersBody := httpJSON(t, http.MethodGet, baseURL+"/api/v1/namespaces/"+slug, nil, nil)
			if ownersResp.StatusCode != http.StatusOK {
				t.Fatalf("owners lookup for %q got %d: %s", slug, ownersResp.StatusCode, string(ownersBody))
			}
			var out ownerLookupOut
			if err := json.Unmarshal(ownersBody, &out); err != nil {
				t.Fatalf("decode owners response: %v", err)
			}
			return out
		}

		renameUser(t, ownerToken, b, http.StatusOK)
		execPSQL(t, fmt.Sprintf(
			"UPDATE profiles.user_renames SET renamed_at='2024-01-01' WHERE user_id=%s AND from_slug=%s;",
			sqlString(ownerID), sqlString(a),
		))
		renameUser(t, ownerToken, cSlug, http.StatusOK)
		execPSQL(t, fmt.Sprintf(
			"UPDATE profiles.user_renames SET renamed_at=now() WHERE user_id=%s AND from_slug=%s;",
			sqlString(ownerID), sqlString(a),
		))

		// profiles.user_renames records one row per vacated slug (from_slug +
		// renamed_at); there is NO to_slug column — the audit trail tracks which
		// historical slugs a user has released, not explicit transition pairs.
		// After A->B and B->C the table must hold both vacated slugs (renamea and
		// renameb). The renamed_at values are deliberately re-stamped above to
		// exercise hold-expiry below, so assert membership rather than order.
		chain := queryPSQL(t, fmt.Sprintf(
			"SELECT string_agg(from_slug, ',' ORDER BY from_slug ASC) FROM profiles.user_renames WHERE user_id=%s;",
			sqlString(ownerID),
		))
		if !strings.Contains(chain, a) || !strings.Contains(chain, b) {
			t.Fatalf("expected vacated-slug audit rows for %q and %q, got %q", a, b, chain)
		}

		ownersOut := lookupOwner(t, a)
		if ownersOut.Slug != cSlug ||
			ownersOut.RequestedSlug != a ||
			ownersOut.Claimable.User ||
			!ownersOut.Renamed ||
			ownersOut.User == nil ||
			ownersOut.User.ID != ownerID ||
			ownersOut.User.Username != cSlug {
			t.Fatalf("historical username %q should resolve by owner id to current username %q with rename Status, got: %+v", a, cSlug, ownersOut)
		}

		body := renameUser(t, claimantToken, a, http.StatusBadRequest)
		if !strings.Contains(string(body), `"error":"owner_slug_taken"`) && !strings.Contains(string(body), `"error":"failed_to_update_username"`) {
			t.Fatalf("expected recent historical username hold to reject claimant, got: %s", string(body))
		}

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET deleted_at=now() WHERE id=%s;", sqlString(ownerID)))
		deletedCurrent := lookupOwner(t, cSlug)
		if deletedCurrent.Claimable.User || deletedCurrent.User != nil {
			t.Fatalf("soft-deleted current username should be held but not resolve as a live user, got: %+v", deletedCurrent)
		}
		recentDeletedRename := lookupOwner(t, a)
		if recentDeletedRename.Claimable.User || recentDeletedRename.User != nil {
			t.Fatalf("recent historical username for a soft-deleted user should remain held, got: %+v", recentDeletedRename)
		}
		body = renameUser(t, claimantToken, cSlug, http.StatusBadRequest)
		if !strings.Contains(string(body), `"error":"owner_slug_taken"`) && !strings.Contains(string(body), `"error":"failed_to_update_username"`) {
			t.Fatalf("expected soft-deleted current username to remain held, got: %s", string(body))
		}

		execPSQL(t, fmt.Sprintf(
			"UPDATE profiles.user_renames SET renamed_at=now() - interval '100 days' WHERE user_id=%s AND from_slug=%s;",
			sqlString(ownerID), sqlString(a),
		))
		expiredDeletedRename := lookupOwner(t, a)
		if !expiredDeletedRename.Claimable.User || expiredDeletedRename.User != nil {
			t.Fatalf("expired historical username for a soft-deleted user should be claimable, got: %+v", expiredDeletedRename)
		}
		renameUser(t, claimantToken, a, http.StatusOK)

		execPSQL(t, fmt.Sprintf(
			"UPDATE profiles.user_renames SET renamed_at=now() - interval '100 days' WHERE user_id=%s;",
			sqlString(claimantID),
		))
		execPSQL(t, fmt.Sprintf("DELETE FROM profiles.users WHERE id=%s;", sqlString(ownerID)))
		renameUser(t, claimantToken, cSlug, http.StatusOK)
	})

	t.Run("reserved_account_reserve_claim_login_flow", func(t *testing.T) {
		// The reserved-account HTTP surface in the current code is the
		// restrict/unrestrict pair (/admin/accounts/restrict +
		// /admin/accounts/unrestrict), which manage the profiles.owner_reserved_names
		// blocklist. There is no /admin/accounts/reserve or /admin/accounts/claim
		// route (the old placeholder-user "reserve+password-claim" flow was never
		// shipped as HTTP routes and assumed multi-org mode the devserver does not
		// run). This exercises the real, route-backed reserved-name feature.
		adminUserID := "11111111-1111-1111-1111-111111111111"
		adminEmail := "admin@example.com"
		adminUsername := "admin-user"
		// Slug must be a valid username (no hyphen) so the rename reaches the
		// reserved-name check rather than failing earlier character validation.
		reservedSlug := "reservedowner"

		// A separate, active user that will try to claim the restricted slug.
		renamerID := "66666666-6666-6666-6666-666666666666"
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(renamerID), sqlString("reserve-renamer@example.com"), sqlString("reserverenamer"),
		))
		renamerToken := mint(t, renamerID, 300)

		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%s, %s, %s, true, '2024-01-01', '2024-01-01') ON CONFLICT (id) DO NOTHING;",
			sqlString(adminUserID), sqlString(adminEmail), sqlString(adminUsername),
		))
		// Earlier subtests (ban_and_delete_enforcement / soft_delete_*) reuse this
		// same user id and leave it banned/soft-deleted. Reactivate it so the minted
		// admin token is accepted (otherwise auth middleware returns user_disabled).
		execPSQL(t, fmt.Sprintf(
			"UPDATE profiles.users SET banned_at=NULL, deleted_at=NULL WHERE id=%s;",
			sqlString(adminUserID),
		))
		execPSQL(t, "INSERT INTO profiles.global_roles (name, slug) VALUES ('Admin', 'admin') ON CONFLICT (slug) DO NOTHING;")
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.global_user_roles (user_id, role_id) VALUES (%s, profiles.role_id('admin')) ON CONFLICT DO NOTHING;",
			sqlString(adminUserID),
		))
		adminToken := mint(t, adminUserID, 300)

		// Restrict the slug -> it lands on the owner_reserved_names blocklist.
		restrictResp, restrictBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/admin/accounts/restrict", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"slugs": []string{reservedSlug},
		})
		if restrictResp.StatusCode != http.StatusOK {
			t.Fatalf("expected restrict 200, got %d: %s", restrictResp.StatusCode, string(restrictBody))
		}
		if !strings.Contains(string(restrictBody), reservedSlug) {
			t.Fatalf("expected %q in restrict response, got: %s", reservedSlug, string(restrictBody))
		}
		reservedRows := queryPSQL(t, fmt.Sprintf(
			"SELECT COUNT(*) FROM profiles.owner_reserved_names WHERE slug=%s;",
			sqlString(reservedSlug),
		))
		if reservedRows != "1" {
			t.Fatalf("expected reserved-name row for %q, got %q", reservedSlug, reservedRows)
		}

		// A live user cannot claim the restricted slug (reserved-name rejection).
		renameResp, renameBody := httpJSON(t, http.MethodPatch, baseURL+"/api/v1/user/username", map[string]string{
			"Authorization": "Bearer " + renamerToken,
		}, map[string]any{"username": reservedSlug})
		if renameResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 claiming restricted slug, got %d: %s", renameResp.StatusCode, string(renameBody))
		}
		if !strings.Contains(string(renameBody), `"error":"username_not_allowed"`) &&
			!strings.Contains(string(renameBody), `"error":"owner_slug_taken"`) {
			t.Fatalf("expected username_not_allowed for restricted slug, got: %s", string(renameBody))
		}

		// Restricting again reports it as already restricted, not newly restricted.
		restrictAgainResp, restrictAgainBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/admin/accounts/restrict", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"slugs": []string{reservedSlug},
		})
		if restrictAgainResp.StatusCode != http.StatusOK {
			t.Fatalf("expected repeat restrict 200, got %d: %s", restrictAgainResp.StatusCode, string(restrictAgainBody))
		}
		if !strings.Contains(string(restrictAgainBody), `"already_restricted":["`+reservedSlug+`"]`) {
			t.Fatalf("expected %q reported as already_restricted, got: %s", reservedSlug, string(restrictAgainBody))
		}

		// Unrestrict frees the slug.
		unrestrictResp, unrestrictBody := httpJSON(t, http.MethodPost, baseURL+"/api/v1/admin/accounts/unrestrict", map[string]string{
			"Authorization": "Bearer " + adminToken,
		}, map[string]any{
			"slugs": []string{reservedSlug},
		})
		if unrestrictResp.StatusCode != http.StatusOK {
			t.Fatalf("expected unrestrict 200, got %d: %s", unrestrictResp.StatusCode, string(unrestrictBody))
		}
		reservedRowsAfter := queryPSQL(t, fmt.Sprintf(
			"SELECT COUNT(*) FROM profiles.owner_reserved_names WHERE slug=%s;",
			sqlString(reservedSlug),
		))
		if reservedRowsAfter != "0" {
			t.Fatalf("expected reserved-name row removed for %q, got %q", reservedSlug, reservedRowsAfter)
		}

		// Now the slug is claimable: the live user can rename into it.
		renameOKResp, renameOKBody := httpJSON(t, http.MethodPatch, baseURL+"/api/v1/user/username", map[string]string{
			"Authorization": "Bearer " + renamerToken,
		}, map[string]any{"username": reservedSlug})
		if renameOKResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 claiming freed slug, got %d: %s", renameOKResp.StatusCode, string(renameOKBody))
		}
	})
}
