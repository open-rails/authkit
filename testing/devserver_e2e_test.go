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

	authhttp "github.com/PaulFidika/authkit/adapters/http"
	"github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	"github.com/PaulFidika/authkit/password"
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
			lastErr = fmt.Errorf("status=%d", resp.StatusCode)
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

	composeFile := filepath.Join(repoRoot, "docker-compose.devserver.yaml")
	overridePath := filepath.Join(t.TempDir(), "docker-compose.override.yaml")
	project := fmt.Sprintf("authkit_e2e_%d", time.Now().UnixNano())
	mintSecret := fmt.Sprintf("secret-%d", time.Now().UnixNano())

	override := fmt.Sprintf(`services:
  postgres:
    ports: []
  issuer:
    ports:
      - "8080"
    environment:
      AUTHKIT_DEV_MINT_SECRET: %q
`, mintSecret)
	if err := os.WriteFile(overridePath, []byte(override), 0600); err != nil {
		t.Fatalf("write override: %v", err)
	}

	c := composeCLI{
		base: composeBase,
		dir:  repoRoot,
		env:  []string{"COMPOSE_PROJECT_NAME=" + project},
	}

	t.Cleanup(func() {
		_ = c.runMaybe("-f", composeFile, "-f", overridePath, "down", "-v", "--remove-orphans")
	})

	c.run(t, "-f", composeFile, "-f", overridePath, "up", "-d", "--build", "--remove-orphans")

	rawPort := c.run(t, "-f", composeFile, "-f", overridePath, "port", "issuer", "8080")
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
	aud := "billing-app"

	t.Run("mint_guard", func(t *testing.T) {
		resp, _ := httpJSON(t, http.MethodPost, baseURL+"/auth/dev/mint", nil, map[string]any{
			"sub": "11111111-1111-1111-1111-111111111111",
			"aud": aud,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}

		resp, _ = httpJSON(t, http.MethodPost, baseURL+"/auth/dev/mint", map[string]string{
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
		resp, raw := httpJSON(t, http.MethodPost, baseURL+"/auth/dev/mint", map[string]string{
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

		accept := core.AcceptConfig{
			Issuers: []core.IssuerAccept{
				{
					Issuer:    issuer,
					Audiences: []string{aud},
					JWKSURL:   baseURL + "/.well-known/jwks.json",
				},
			},
			Algorithms: []string{"RS256"},
			Skew:       1 * time.Millisecond,
		}
		ver := authhttp.NewVerifier(accept)

		claims, err := ver.Verify(token)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if got := fmt.Sprint(claims["sub"]); got != "11111111-1111-1111-1111-111111111111" {
			t.Fatalf("bad sub: %q", got)
		}

		time.Sleep(2 * time.Second)
		_, err = ver.Verify(token)
		if err == nil {
			t.Fatalf("expected expired token to fail verification")
		}
	})

	execPSQL := func(t *testing.T, sql string) {
		t.Helper()
		c.run(t, "-f", composeFile, "-f", overridePath, "exec", "-T", "postgres",
			"psql", "-U", "admin", "-d", "authkit_db", "-v", "ON_ERROR_STOP=1", "-c", sql)
	}

	t.Run("minted_token_can_call_user_me", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%q, %q, %q, true, '2024-01-01', '2024-01-01');",
			userID, "test@example.com", "testuser",
		))

		token := mint(t, userID, 300)
		resp, body := httpJSON(t, http.MethodGet, baseURL+"/auth/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("admin_gate_db_backed", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		execPSQL(t, "INSERT INTO profiles.roles (name, slug) VALUES ('Admin', 'admin') ON CONFLICT (slug) DO NOTHING;")
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.user_roles (user_id, role_id) VALUES (%q, profiles.role_id('admin')) ON CONFLICT DO NOTHING;",
			userID,
		))

		token := mint(t, userID, 300)
		resp, body := httpJSON(t, http.MethodGet, baseURL+"/auth/admin/users", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("ban_and_delete_enforcement", func(t *testing.T) {
		userID := "11111111-1111-1111-1111-111111111111"
		token := mint(t, userID, 300)

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=now() WHERE id=%q;", userID))
		resp, _ := httpJSON(t, http.MethodGet, baseURL+"/auth/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for banned user, got %d", resp.StatusCode)
		}

		execPSQL(t, fmt.Sprintf("UPDATE profiles.users SET banned_at=NULL, deleted_at=now() WHERE id=%q;", userID))
		resp, _ = httpJSON(t, http.MethodGet, baseURL+"/auth/user/me", map[string]string{
			"Authorization": "Bearer " + token,
		}, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 for deleted user, got %d", resp.StatusCode)
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
			"INSERT INTO profiles.users (id, email, username, email_verified, created_at, updated_at) VALUES (%q, %q, %q, true, '2024-01-01', '2024-01-01');",
			userID, email, username,
		))
		execPSQL(t, fmt.Sprintf(
			"INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo) VALUES (%q, %q, 'argon2id');",
			userID, hash,
		))

		loginResp, loginBody := httpJSON(t, http.MethodPost, baseURL+"/auth/password/login", nil, map[string]any{
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

		refreshResp, refreshBody := httpJSON(t, http.MethodPost, baseURL+"/auth/token", nil, map[string]any{
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

		logoutResp, logoutBody := httpJSON(t, http.MethodDelete, baseURL+"/auth/logout", map[string]string{
			"Authorization": "Bearer " + loginOut.AccessToken,
		}, nil)
		if logoutResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", logoutResp.StatusCode, string(logoutBody))
		}

		refreshResp2, refreshBody2 := httpJSON(t, http.MethodPost, baseURL+"/auth/token", nil, map[string]any{
			"grant_type":    "refresh_token",
			"refresh_token": refreshOut.RefreshToken,
		})
		if refreshResp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout, got %d: %s", refreshResp2.StatusCode, string(refreshBody2))
		}
	})
}
