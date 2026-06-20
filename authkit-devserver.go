package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/authkit/core"
	authhttp "github.com/open-rails/authkit/http"
	jwtkit "github.com/open-rails/authkit/jwt"
	pgmigrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/open-rails/migratekit"
)

type config struct {
	ListenAddr               string
	Issuer                   string
	DBURL                    string
	DevMode                  bool
	DevMintSecret            string
	RegistrationVerification core.RegistrationVerificationPolicy
	MigrateOnStart           bool
	IssuedAudiences          []string
	ExpectedAudiences        []string
	Environment              string
	// Org/RBAC knobs. Default to authkit's zero values (single-org, no
	// catalog) so existing deployments are unaffected; the e2e suite sets
	// these to exercise the multi-org API-key/RBAC surface against a real server.
	APIKeyPrefix                string
	PermissionCatalog           []string
	OrgManifestPath             string
	ReconcileOrgManifestOnStart bool
	BootstrapManifestPath       string
	ReconcileBootstrapOnStart   bool
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fatal(err)
	}

	cmd := "serve"
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		cmd = strings.TrimSpace(os.Args[1])
	}

	switch cmd {
	case "serve":
		if err := runServe(cfg); err != nil {
			fatal(err)
		}
	case "migrate":
		if err := runMigrate(cfg); err != nil {
			fatal(err)
		}
	case "org-manifest":
		if len(os.Args) < 3 || strings.TrimSpace(os.Args[2]) != "apply" {
			fatal(fmt.Errorf("unknown command %q (supported: serve, migrate, bootstrap apply, org-manifest apply)", strings.Join(os.Args[1:], " ")))
		}
		if err := runOrgManifestApply(cfg); err != nil {
			fatal(err)
		}
	case "bootstrap":
		if len(os.Args) < 3 || strings.TrimSpace(os.Args[2]) != "apply" {
			fatal(fmt.Errorf("unknown command %q (supported: serve, migrate, bootstrap apply, org-manifest apply)", strings.Join(os.Args[1:], " ")))
		}
		if err := runBootstrapApply(cfg, os.Args[3:]); err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("unknown command %q (supported: serve, migrate, bootstrap apply, org-manifest apply)", cmd))
	}
}

func loadConfig() (*config, error) {
	issuedAudiences := parseCSVEnv("DEVSERVER_ISSUED_AUDIENCES", []string{"billing-app"})
	expectedAudiences := parseCSVEnv("DEVSERVER_EXPECTED_AUDIENCES", issuedAudiences)

	c := &config{
		ListenAddr:                  envOr("DEVSERVER_LISTEN_ADDR", ":8080"),
		Issuer:                      strings.TrimRight(envOr("DEVSERVER_ISSUER", ""), "/"),
		DBURL:                       firstEnv("DB_URL", "DATABASE_URL"),
		DevMode:                     envBool("DEVSERVER_DEV_MODE", false),
		DevMintSecret:               envOr("DEVSERVER_DEV_MINT_SECRET", ""),
		MigrateOnStart:              envBool("DEVSERVER_MIGRATE_ON_START", true),
		IssuedAudiences:             issuedAudiences,
		ExpectedAudiences:           expectedAudiences,
		Environment:                 envOr("DEVSERVER_ENVIRONMENT", "dev"),
		RegistrationVerification:    core.RegistrationVerificationPolicy(strings.ToLower(strings.TrimSpace(envOr("DEVSERVER_REGISTRATION_VERIFICATION", "none")))),
		APIKeyPrefix:                strings.TrimSpace(firstEnv("DEVSERVER_API_KEY_PREFIX", "DEVSERVER_TOKEN_PREFIX")),
		PermissionCatalog:           parseCSVEnv("DEVSERVER_PERMISSION_CATALOG", nil),
		OrgManifestPath:             strings.TrimSpace(envOr("DEVSERVER_ORG_MANIFEST_PATH", "")),
		ReconcileOrgManifestOnStart: envBool("DEVSERVER_RECONCILE_ORG_MANIFEST_ON_START", false),
		BootstrapManifestPath:       strings.TrimSpace(envOr("AUTHKIT_BOOTSTRAP_PATH", core.DefaultBootstrapManifestPath)),
		ReconcileBootstrapOnStart:   envBool("AUTHKIT_BOOTSTRAP_ON_START", false),
	}
	if c.Issuer == "" {
		return nil, fmt.Errorf("DEVSERVER_ISSUER is required")
	}
	if c.DBURL == "" {
		return nil, fmt.Errorf("DB_URL (or DATABASE_URL) is required")
	}
	if c.DevMode && c.DevMintSecret == "" {
		return nil, fmt.Errorf("DEVSERVER_DEV_MINT_SECRET is required when DEVSERVER_DEV_MODE=true")
	}
	switch c.RegistrationVerification {
	case core.RegistrationVerificationNone, core.RegistrationVerificationOptional, core.RegistrationVerificationRequired:
	default:
		return nil, fmt.Errorf("DEVSERVER_REGISTRATION_VERIFICATION must be one of: none, optional, required")
	}
	return c, nil
}

func runServe(cfg *config) error {
	ctx := context.Background()

	if cfg.MigrateOnStart {
		if err := runMigrations(ctx, cfg.DBURL); err != nil {
			return err
		}
	}

	pg, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pg.Close()

	keySource, err := jwtkit.NewAutoKeySource()
	if err != nil {
		return fmt.Errorf("load jwt keys: %w", err)
	}

	svc, err := authhttp.NewService(core.Config{
		Issuer:                   cfg.Issuer,
		IssuedAudiences:          cfg.IssuedAudiences,
		ExpectedAudiences:        cfg.ExpectedAudiences,
		Keys:                     keySource,
		Environment:              cfg.Environment,
		RegistrationVerification: cfg.RegistrationVerification,
		APIKeyPrefix:             cfg.APIKeyPrefix,
		Permissions:        toPermissionDefs(cfg.PermissionCatalog),
	})
	if err != nil {
		return err
	}
	svc.WithPostgres(pg)
	if cfg.ReconcileBootstrapOnStart {
		if _, err := reconcileBootstrapManifest(ctx, svc.Core(), cfg.BootstrapManifestPath, false); err != nil {
			return err
		}
	}
	if cfg.ReconcileOrgManifestOnStart {
		if _, err := reconcileOrgManifest(ctx, svc.Core(), cfg.OrgManifestPath); err != nil {
			return err
		}
	}

	apiH := svc.APIHandler()
	oidcH := svc.OIDCHandler()
	jwksH := svc.JWKSHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	// Public: consumers (e.g., billing) fetch keys here.
	mux.Handle("/.well-known/jwks.json", jwksH)
	// Auth routes: the devserver mirrors the recommended host mount at /api/v1.
	apiPrefix := "/api/v1"
	mux.Handle(apiPrefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dev-only: mint arbitrary JWTs for downstream service E2E tests.
		if cfg.DevMode && r.Method == http.MethodPost && r.URL.Path == apiPrefix+"/dev/mint" {
			devMintHandler(cfg.Issuer, keySource.ActiveSigner(), cfg.DevMintSecret).ServeHTTP(w, r)
			return
		}
		// Dev-only: reflect the authenticated principal (user OR API-key service principal)
		// so E2E tests can assert how a token resolved through the real verifier.
		if cfg.DevMode && r.Method == http.MethodGet && r.URL.Path == apiPrefix+"/dev/whoami" {
			devWhoamiHandler(svc).ServeHTTP(w, r)
			return
		}
		// Browser flows are GET-only (/login and /callback). Link-start endpoints live in the JSON API.
		if r.Method == http.MethodGet &&
			strings.HasPrefix(r.URL.Path, apiPrefix+"/oidc/") &&
			(strings.HasSuffix(r.URL.Path, "/login") || strings.HasSuffix(r.URL.Path, "/callback")) {
			http.StripPrefix(apiPrefix, oidcH).ServeHTTP(w, r)
			return
		}
		http.StripPrefix(apiPrefix, apiH).ServeHTTP(w, r)
	}))

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func runMigrate(cfg *config) error {
	ctx := context.Background()
	return runMigrations(ctx, cfg.DBURL)
}

func runOrgManifestApply(cfg *config) error {
	ctx := context.Background()
	pg, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pg.Close()

	svc := core.NewService(core.Options{
		Issuer:            cfg.Issuer,
		APIKeyPrefix:      cfg.APIKeyPrefix,
		Permissions: toPermissionDefs(cfg.PermissionCatalog),
	}, core.Keyset{}).WithPostgres(pg)
	result, err := reconcileOrgManifest(ctx, svc, cfg.OrgManifestPath)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]int{
		"orgs":            result.Orgs,
		"issuers":         result.Issuers,
		"roles":           result.Roles,
		"api_keys_minted": result.APIKeysMinted,
		"api_keys_kept":   result.APIKeysKept,
	})
}

func runBootstrapApply(cfg *config, args []string) error {
	ctx := context.Background()
	path := strings.TrimSpace(flagValue(args, "--file", "-f", cfg.BootstrapManifestPath))
	dryRun := flagBool(args, "--dry-run")
	pg, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pg.Close()

	svc := core.NewService(core.Options{
		Issuer:            cfg.Issuer,
		APIKeyPrefix:      cfg.APIKeyPrefix,
		Permissions: toPermissionDefs(cfg.PermissionCatalog),
	}, core.Keyset{}).WithPostgres(pg)
	result, err := reconcileBootstrapManifest(ctx, svc, path, dryRun)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func reconcileOrgManifest(ctx context.Context, svc *core.Service, path string) (core.OrgManifestResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return core.OrgManifestResult{}, fmt.Errorf("DEVSERVER_ORG_MANIFEST_PATH is required")
	}
	manifest, err := core.ParseOrgManifestYAMLFile(path)
	if err != nil {
		return core.OrgManifestResult{}, fmt.Errorf("read org manifest: %w", err)
	}
	result, err := svc.ReconcileOrgManifest(ctx, manifest, core.FileOrgManifestTokenStore{})
	if err != nil {
		return core.OrgManifestResult{}, fmt.Errorf("reconcile org manifest: %w", err)
	}
	return result, nil
}

func reconcileBootstrapManifest(ctx context.Context, svc *core.Service, path string, dryRun bool) (core.BootstrapManifestResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = core.DefaultBootstrapManifestPath
	}
	manifest, err := core.LoadBootstrapManifestFile(path)
	if err != nil {
		return core.BootstrapManifestResult{}, fmt.Errorf("read bootstrap manifest: %w", err)
	}
	result, err := svc.ReconcileBootstrapManifest(ctx, manifest, core.FileBootstrapTokenStore{}, core.BootstrapReconcileOptions{DryRun: dryRun})
	if err != nil {
		return core.BootstrapManifestResult{}, fmt.Errorf("reconcile bootstrap manifest: %w", err)
	}
	return result, nil
}

func runMigrations(ctx context.Context, dbURL string) error {
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("open sql db: %w", err)
	}
	defer sqlDB.Close()

	// AuthKit migrations rely on pgcrypto for deterministic UUIDv5 helpers.
	if _, err := sqlDB.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		return fmt.Errorf("enable pgcrypto: %w", err)
	}

	// Same runner host applications use: migratekit, name-tracked per app in
	// public.migrations.
	ms, err := migratekit.LoadFromFS(pgmigrations.FS)
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	if err := migratekit.NewPostgres(sqlDB, "authkit").ApplyMigrations(ctx, ms); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func flagValue(args []string, long, short, def string) string {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		for _, name := range []string{long, short} {
			if arg == name && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(arg, name+"=") {
				return strings.TrimPrefix(arg, name+"=")
			}
		}
	}
	return def
}

func flagBool(args []string, name string) bool {
	for _, arg := range args {
		if strings.TrimSpace(arg) == name {
			return true
		}
	}
	return false
}

type mintRequest struct {
	Sub              string   `json:"sub" binding:"required"`
	Aud              string   `json:"aud" binding:"required"`
	Email            string   `json:"email"`
	Roles            []string `json:"roles"`
	GlobalRoles      []string `json:"global_roles"`
	Entitlements     []string `json:"entitlements"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
}

type mintResponse struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
}

func toPermissionDefs(names []string) []core.PermissionDef {
	if len(names) == 0 {
		return nil
	}
	defs := make([]core.PermissionDef, 0, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			defs = append(defs, core.PermissionDef{Name: n})
		}
	}
	return defs
}

// devWhoamiHandler reflects the authenticated principal as resolved by the real
// verifier (JWT user OR branded API key), behind the standard auth middleware.
// Dev-only; used by the RBAC E2E suite to assert API-key resolution.
func devWhoamiHandler(svc *authhttp.Service) http.Handler {
	reflect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := authhttp.ClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"org":         cl.Org,
			"permissions": cl.Permissions,
			"is_service":  cl.IsService(),
			"user_id":     cl.UserID,
		})
	})
	return authhttp.Required(svc.Verifier())(reflect)
}

func devMintHandler(issuer string, signer jwtkit.Signer, secret string) http.Handler {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !devSecretOK(r.Header.Get("Authorization"), r.Header.Get("X-DEV-SECRET"), secret) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}

		var req mintRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		req.Sub = strings.TrimSpace(req.Sub)
		req.Aud = strings.TrimSpace(req.Aud)
		req.Email = strings.TrimSpace(req.Email)
		if req.Sub == "" || req.Aud == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "sub and aud are required"})
			return
		}

		expiresIn := req.ExpiresInSeconds
		if expiresIn <= 0 {
			expiresIn = 3600
		}
		now := time.Now()
		expiresAt := now.Add(time.Duration(expiresIn) * time.Second)

		claims := map[string]any{
			"iss": issuer,
			"sub": req.Sub,
			"aud": []string{req.Aud},
			"iat": now.Unix(),
			"exp": expiresAt.Unix(),
		}
		if req.Email != "" {
			claims["email"] = req.Email
		}
		if len(req.Roles) > 0 {
			claims["roles"] = req.Roles
		}
		if len(req.GlobalRoles) > 0 {
			claims["global_roles"] = req.GlobalRoles
		}
		if len(req.Entitlements) > 0 {
			claims["entitlements"] = req.Entitlements
		}

		hs, ok := signer.(jwtkit.HeaderSigner)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "header signer required"})
			return
		}
		token, err := hs.SignWithHeaders(r.Context(), claims, map[string]any{"typ": jwtkit.AccessTokenType})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to sign token"})
			return
		}
		writeJSON(w, http.StatusOK, mintResponse{
			Token:     token,
			TokenType: "Bearer",
			ExpiresAt: expiresAt,
		})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func devSecretOK(authHeader, devHeader, secret string) bool {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return false
	}

	if strings.TrimSpace(devHeader) != "" {
		return strings.TrimSpace(devHeader) == secret
	}

	authHeader = strings.TrimSpace(authHeader)
	const prefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
		return false
	}
	return strings.TrimSpace(authHeader[len(prefix):]) == secret
}

func parseCSVEnv(canonicalKey string, fallback []string) []string {
	raw, ok := envValue(canonicalKey)
	if !ok {
		return fallback
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func envOr(canonicalKey, fallback string) string {
	if v, ok := envValue(canonicalKey); ok {
		return strings.TrimSpace(v)
	}
	return fallback
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func envBool(canonicalKey string, fallback bool) bool {
	raw, ok := envValue(canonicalKey)
	if !ok {
		return fallback
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		warnf("invalid boolean in %s=%q; using default %t", canonicalKey, raw, fallback)
		return fallback
	}
	return b
}

func envValue(canonicalKey string) (string, bool) {
	if v := strings.TrimSpace(os.Getenv(canonicalKey)); v != "" {
		return v, true
	}
	return "", false
}

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[authkit-devserver] "+format+"\n", args...)
}

func fatal(err error) {
	if err == nil {
		os.Exit(0)
	}
	if errors.Is(err, http.ErrServerClosed) {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
