//go:build e2e

package testing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDevserverBootstrapManifestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in -short")
	}

	composeBase := findCompose(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Dir(wd)

	mountDir := t.TempDir()
	if err := os.Chmod(mountDir, 0o777); err != nil {
		t.Fatalf("chmod bootstrap mount dir: %v", err)
	}
	staticPEM := generateBootstrapPublicKeyPEM(t)
	manifest := fmt.Sprintf(`users:
  - ref: operator
    email: bootstrap-operator@example.com
    username: bootstrapoperator
    email_verified: true
    password:
      plaintext: BootstrapPassword123!
    global_roles: ["admin"]
    metadata:
      source: devserver-bootstrap-e2e

global_roles:
  - slug: admin
    name: Admin

orgs:
  - slug: bootstrap-org
    issuers:
      - slug: bootstrap-jwks
        issuer: https://bootstrap-jwks.example/issuer
        jwks_uri: https://bootstrap-jwks.example/.well-known/jwks.json
        audiences: ["billing-app"]
        enabled: true
      - slug: bootstrap-static
        issuer: https://bootstrap-static.example/issuer
        mode: static
        public_keys:
          - kid: static-kid
            public_key_pem: |
%s
        audiences: ["billing-app"]
        enabled: true
    roles:
      - name: operator
        permissions:
          - org:read
          - org:api_keys:manage
          - endpoint:deploy
          - repo:read
          - openrails:catalog:write
    memberships:
      - user_ref: operator
        role: operator
    api_keys:
      - name: bootstrap-runtime
        permissions:
          - endpoint:deploy
          - repo:read
          - openrails:catalog:write
        resources:
          - kind: openrails.merchant
            id: bootstrap-org
        output:
          file: /bootstrap/runtime-token
`, indent(staticPEM, 14))
	manifestPath := filepath.Join(mountDir, "bootstrap.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	tokenOutputPath := filepath.Join(mountDir, "runtime-token")
	if err := os.WriteFile(tokenOutputPath, nil, 0o666); err != nil {
		t.Fatalf("precreate API key output: %v", err)
	}
	if err := os.Chmod(tokenOutputPath, 0o666); err != nil {
		t.Fatalf("chmod API key output: %v", err)
	}

	composeFile := filepath.Join(t.TempDir(), "docker-compose.bootstrap.yaml")
	project := fmt.Sprintf("authkit_bootstrap_e2e_%d", time.Now().UnixNano())
	mintSecret := fmt.Sprintf("secret-%d", time.Now().UnixNano())
	aud := "billing-app"
	compose := fmt.Sprintf(`services:
  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_DB: authkit_db
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: admin_password
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin -d authkit_db"]
      interval: 5s
      timeout: 3s
      retries: 20

  issuer:
    build:
      context: %q
      dockerfile: Dockerfile.devserver
      network: host
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080"
    environment:
      ENV: "dev"
      DEVSERVER_LISTEN_ADDR: ":8080"
      DEVSERVER_ISSUER: "http://issuer:8080"
      DEVSERVER_ISSUED_AUDIENCES: "billing-app"
      DEVSERVER_EXPECTED_AUDIENCES: "billing-app"
      DB_URL: "postgres://admin:admin_password@postgres:5432/authkit_db?sslmode=disable"
      DEVSERVER_DEV_MODE: "true"
      DEVSERVER_DEV_MINT_SECRET: %q
      DEVSERVER_TOKEN_PREFIX: "cozy"
      DEVSERVER_PERMISSION_CATALOG: "endpoint:deploy,repo:read,openrails:catalog:write"
      AUTHKIT_BOOTSTRAP_ON_START: "true"
      AUTHKIT_BOOTSTRAP_PATH: "/bootstrap/bootstrap.yaml"
    volumes:
      - %q
      - authkit_runtime_keys:/.runtime/authkit

volumes:
  authkit_runtime_keys:
`, repoRoot, mintSecret, mountDir+":/bootstrap")
	if err := os.WriteFile(composeFile, []byte(compose), 0600); err != nil {
		t.Fatalf("write compose file: %v", err)
	}

	c := composeCLI{
		base: composeBase,
		dir:  repoRoot,
		env:  []string{"COMPOSE_PROJECT_NAME=" + project},
	}
	t.Cleanup(func() {
		_ = c.runMaybe("-f", composeFile, "down", "-v", "--remove-orphans")
	})

	c.run(t, "-f", composeFile, "up", "-d", "--build", "--remove-orphans")
	rawPort := c.run(t, "-f", composeFile, "port", "issuer", "8080")
	baseURL := "http://127.0.0.1:" + parsePort(t, rawPort)
	api := baseURL + "/api/v1"
	waitForHTTP200WithComposeLogs(t, c, composeFile, baseURL+"/healthz", 90*time.Second)

	loginResp, loginBody := httpJSON(t, http.MethodPost, api+"/password/login", nil, map[string]any{
		"email":    "bootstrap-operator@example.com",
		"password": "BootstrapPassword123!",
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap user login: expected 200, got %d: %s", loginResp.StatusCode, string(loginBody))
	}
	var loginOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(loginBody, &loginOut); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if strings.TrimSpace(loginOut.AccessToken) == "" {
		t.Fatalf("bootstrap user login returned empty access_token")
	}

	meResp, meBody := httpJSON(t, http.MethodGet, api+"/user/me", map[string]string{
		"Authorization": "Bearer " + loginOut.AccessToken,
	}, nil)
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap user /user/me: expected 200, got %d: %s", meResp.StatusCode, string(meBody))
	}

	adminResp, adminBody := httpJSON(t, http.MethodGet, api+"/admin/users", map[string]string{
		"Authorization": "Bearer " + loginOut.AccessToken,
	}, nil)
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap global admin /admin/users: expected 200, got %d: %s", adminResp.StatusCode, string(adminBody))
	}

	tokenRaw, err := os.ReadFile(filepath.Join(mountDir, "runtime-token"))
	if err != nil {
		t.Fatalf("read generated API key: %v", err)
	}
	serviceToken := strings.TrimSpace(string(tokenRaw))
	if !strings.HasPrefix(serviceToken, "cozy_st_") {
		t.Fatalf("generated API key has wrong marker: %q", serviceToken)
	}
	whoResp, whoBody := httpJSON(t, http.MethodGet, api+"/dev/whoami", map[string]string{
		"Authorization": "Bearer " + serviceToken,
	}, nil)
	if whoResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap API key /dev/whoami: expected 200, got %d: %s", whoResp.StatusCode, string(whoBody))
	}
	var who struct {
		Org         string   `json:"org"`
		Permissions []string `json:"permissions"`
		IsService   bool     `json:"is_service"`
		UserID      string   `json:"user_id"`
	}
	if err := json.Unmarshal(whoBody, &who); err != nil {
		t.Fatalf("decode whoami: %v", err)
	}
	if who.Org != "bootstrap-org" || !who.IsService || who.UserID != "" {
		t.Fatalf("unexpected service principal: %+v", who)
	}
	for _, perm := range []string{"endpoint:deploy", "repo:read", "openrails:catalog:write"} {
		if !stringInSlice(who.Permissions, perm) {
			t.Fatalf("API key permissions=%v, want %q", who.Permissions, perm)
		}
	}

	remoteResp, remoteBody := httpJSON(t, http.MethodGet, api+"/remote-applications", map[string]string{
		"Authorization": "Bearer " + loginOut.AccessToken,
	}, nil)
	if remoteResp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap remote applications list: expected 200, got %d: %s", remoteResp.StatusCode, string(remoteBody))
	}
	var remoteOut struct {
		RemoteApplications []struct {
			Slug       string `json:"slug"`
			Issuer     string `json:"issuer"`
			JWKSURI    string `json:"jwks_uri"`
			Mode       string `json:"mode"`
			PublicKeys []struct {
				KID          string `json:"kid"`
				PublicKeyPEM string `json:"public_key_pem"`
			} `json:"public_keys"`
			Audiences []string `json:"audiences"`
			Enabled   bool     `json:"enabled"`
		} `json:"remote_applications"`
	}
	if err := json.Unmarshal(remoteBody, &remoteOut); err != nil {
		t.Fatalf("decode remote applications: %v", err)
	}
	bySlug := map[string]struct {
		Issuer     string
		JWKSURI    string
		Mode       string
		PublicKeys []struct {
			KID          string `json:"kid"`
			PublicKeyPEM string `json:"public_key_pem"`
		}
		Audiences []string
		Enabled   bool
	}{}
	for _, item := range remoteOut.RemoteApplications {
		bySlug[item.Slug] = struct {
			Issuer     string
			JWKSURI    string
			Mode       string
			PublicKeys []struct {
				KID          string `json:"kid"`
				PublicKeyPEM string `json:"public_key_pem"`
			}
			Audiences []string
			Enabled   bool
		}{Issuer: item.Issuer, JWKSURI: item.JWKSURI, Mode: item.Mode, PublicKeys: item.PublicKeys, Audiences: item.Audiences, Enabled: item.Enabled}
	}
	jwks := bySlug["bootstrap-jwks"]
	if jwks.Issuer != "https://bootstrap-jwks.example/issuer" || jwks.Mode != "jwks" || jwks.JWKSURI != "https://bootstrap-jwks.example/.well-known/jwks.json" || !jwks.Enabled || !stringInSlice(jwks.Audiences, aud) {
		t.Fatalf("unexpected JWKS remote application: %+v", jwks)
	}
	static := bySlug["bootstrap-static"]
	if static.Issuer != "https://bootstrap-static.example/issuer" || static.Mode != "static" || static.JWKSURI != "" || !static.Enabled || !stringInSlice(static.Audiences, aud) {
		t.Fatalf("unexpected static remote application: %+v", static)
	}
	if len(static.PublicKeys) != 1 || static.PublicKeys[0].KID != "static-kid" || !strings.Contains(static.PublicKeys[0].PublicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Fatalf("unexpected static public keys: %+v", static.PublicKeys)
	}
}

func generateBootstrapPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate static key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal static public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func indent(s string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

func stringInSlice(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func waitForHTTP200WithComposeLogs(t *testing.T, c composeCLI, composeFile, url string, timeout time.Duration) {
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
	logs := c.run(t, "-f", composeFile, "logs", "--no-color", "issuer", "postgres")
	t.Fatalf("timed out waiting for %s: %v\ncompose logs:\n%s", url, lastErr, logs)
}
