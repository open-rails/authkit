package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	authhttp "github.com/PaulFidika/authkit/adapters/http"
	"github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	pgmigrations "github.com/PaulFidika/authkit/migrations/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type config struct {
	ListenAddr     string
	Issuer         string
	DBURL          string
	DevMode        bool
	DevMintSecret  string
	MigrateOnStart bool
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
	default:
		fatal(fmt.Errorf("unknown command %q (supported: serve, migrate)", cmd))
	}
}

func loadConfig() (*config, error) {
	c := &config{
		ListenAddr:     envOr("AUTHKIT_LISTEN_ADDR", ":8080"),
		Issuer:         strings.TrimRight(strings.TrimSpace(os.Getenv("AUTHKIT_ISSUER")), "/"),
		DBURL:          firstEnv("DB_URL", "DATABASE_URL"),
		DevMode:        envBool("AUTHKIT_DEV_MODE", false),
		DevMintSecret:  strings.TrimSpace(os.Getenv("AUTHKIT_DEV_MINT_SECRET")),
		MigrateOnStart: envBool("AUTHKIT_MIGRATE_ON_START", true),
	}
	if c.Issuer == "" {
		return nil, fmt.Errorf("AUTHKIT_ISSUER is required (e.g. http://issuer:8080 or http://localhost:8080)")
	}
	if c.DBURL == "" {
		return nil, fmt.Errorf("DB_URL (or DATABASE_URL) is required")
	}
	if c.DevMode && c.DevMintSecret == "" {
		return nil, fmt.Errorf("AUTHKIT_DEV_MINT_SECRET is required when AUTHKIT_DEV_MODE=true")
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

	issuedAudiences := parseCSVEnv("AUTHKIT_ISSUED_AUDIENCES", []string{"billing-app"})
	expectedAudiences := parseCSVEnv("AUTHKIT_EXPECTED_AUDIENCES", issuedAudiences)

	svc, err := authhttp.NewService(core.Config{
		Issuer:            cfg.Issuer,
		IssuedAudiences:   issuedAudiences,
		ExpectedAudiences: expectedAudiences,
		Keys:              keySource,
	})
	if err != nil {
		return err
	}
	svc.WithPostgres(pg)

	apiH := svc.APIHandler()
	oidcH := svc.OIDCHandler()
	jwksH := svc.JWKSHandler()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	// Public: consumers (e.g., billing) fetch keys here.
	mux.Handle("/.well-known/jwks.json", jwksH)
	// Auth routes: dispatch browser flows vs JSON API.
	mux.Handle("/auth/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dev-only: mint arbitrary JWTs for downstream service E2E tests.
		if cfg.DevMode && r.Method == http.MethodPost && r.URL.Path == "/auth/dev/mint" {
			devMintHandler(cfg.Issuer, keySource.ActiveSigner(), cfg.DevMintSecret).ServeHTTP(w, r)
			return
		}
		// Browser flows are GET-only (/login and /callback). Link-start endpoints live in the JSON API.
		if r.Method == http.MethodGet &&
			(strings.HasPrefix(r.URL.Path, "/auth/oidc/") && (strings.HasSuffix(r.URL.Path, "/login") || strings.HasSuffix(r.URL.Path, "/callback")) ||
				(strings.HasPrefix(r.URL.Path, "/auth/oauth/") && (strings.HasSuffix(r.URL.Path, "/login") || strings.HasSuffix(r.URL.Path, "/callback")))) {
			oidcH.ServeHTTP(w, r)
			return
		}
		apiH.ServeHTTP(w, r)
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

func runMigrations(ctx context.Context, dbURL string) error {
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		return fmt.Errorf("open sql db: %w", err)
	}
	defer sqlDB.Close()

	// AuthKit migrations rely on pgcrypto (gen_random_uuid, digest/sha1).
	if _, err := sqlDB.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		return fmt.Errorf("enable pgcrypto: %w", err)
	}

	files, err := fs.Glob(pgmigrations.FS, "*.up.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no postgres migrations found")
	}
	sortStrings(files)

	for _, name := range files {
		sqlBytes, err := pgmigrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if strings.TrimSpace(string(sqlBytes)) == "" {
			continue
		}
		if _, err := sqlDB.ExecContext(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

func sortStrings(v []string) {
	for i := 0; i < len(v); i++ {
		for j := i + 1; j < len(v); j++ {
			if v[j] < v[i] {
				v[i], v[j] = v[j], v[i]
			}
		}
	}
}

type mintRequest struct {
	Sub              string   `json:"sub" binding:"required"`
	Aud              string   `json:"aud" binding:"required"`
	Email            string   `json:"email"`
	Roles            []string `json:"roles"`
	Entitlements     []string `json:"entitlements"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
}

type mintResponse struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresAt time.Time `json:"expires_at"`
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
		if len(req.Entitlements) > 0 {
			claims["entitlements"] = req.Entitlements
		}

		token, err := signer.Sign(r.Context(), claims)
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

func parseCSVEnv(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
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

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
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

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return b
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
