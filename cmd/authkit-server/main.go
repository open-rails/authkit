// Command authkit-server is the standalone, self-hostable AuthKit server (#142).
// It runs the engine in-process and exposes, on one listener:
//
//   - the browser-facing auth-flow routes (register/login/OIDC/passwordless/…),
//   - the JWKS endpoint downstream verifiers fetch,
//   - the authenticated MANAGEMENT API (POST /v1/call/{Method}) that the
//     authkit/remote Go SDK and non-Go clients drive to provision/manage/mint.
//
// A Go app swaps embedded↔remote with one construction line (embedded.New ↔
// remote.New); both satisfy authkit.Client. main is thin — config comes from env;
// the library does the work (etcd's embed.Config / etcdmain split).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit/embedded"
	authhttp "github.com/open-rails/authkit/http"
	"github.com/open-rails/authkit/server"
)

type config struct {
	listenAddr string
	dbURL      string
	issuer     string
	audiences  []string
	keysPath   string
	schema     string
	env        string
	redisAddr  string
	mgmtToken  string // app→server bearer credential for the management API
	apiPrefix  string
	regVerify  string // registration verification policy: none|optional|required
}

func loadConfig() (*config, error) {
	c := &config{
		listenAddr: envOr("AUTHKIT_LISTEN_ADDR", ":8080"),
		dbURL:      firstEnv("DB_URL", "DATABASE_URL"),
		issuer:     strings.TrimRight(envOr("AUTHKIT_ISSUER", ""), "/"),
		audiences:  splitCSV(envOr("AUTHKIT_AUDIENCES", "authkit")),
		keysPath:   strings.TrimSpace(os.Getenv("AUTHKIT_KEYS_PATH")),
		schema:     strings.TrimSpace(os.Getenv("AUTHKIT_SCHEMA")),
		env:        envOr("AUTHKIT_ENV", "dev"),
		redisAddr:  strings.TrimSpace(os.Getenv("AUTHKIT_REDIS_ADDR")),
		mgmtToken:  strings.TrimSpace(os.Getenv("AUTHKIT_MGMT_TOKEN")),
		apiPrefix:  envOr("AUTHKIT_API_PREFIX", "/api/v1"),
		// Default to "none": a bare standalone server has no email/SMS sender, and
		// "required" verification with no sender is unsatisfiable. Operators set
		// this once they wire a sender (senders are an embedded.New option).
		regVerify: strings.ToLower(envOr("AUTHKIT_REGISTRATION_VERIFICATION", "none")),
	}
	if c.issuer == "" {
		return nil, errors.New("AUTHKIT_ISSUER is required")
	}
	if c.dbURL == "" {
		return nil, errors.New("DB_URL (or DATABASE_URL) is required")
	}
	return c, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("authkit-server: %v", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()

	pg, err := pgxpool.New(ctx, cfg.dbURL)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pg.Close()

	var rdb *redis.Client
	if cfg.redisAddr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.redisAddr})
		defer func() { _ = rdb.Close() }()
	}

	coreCfg := embedded.Config{
		Environment: cfg.env,
		Schema:      cfg.schema,
		Token: embedded.TokenConfig{
			Issuer:            cfg.issuer,
			IssuedAudiences:   cfg.audiences,
			ExpectedAudiences: cfg.audiences,
		},
		Keys:         embedded.KeysConfig{Path: cfg.keysPath},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationPolicy(cfg.regVerify)},
	}

	var engineOpts []embedded.Option
	var httpOpts []authhttp.Option
	if rdb != nil {
		engineOpts = append(engineOpts, embedded.WithRedis(rdb))
		httpOpts = append(httpOpts, authhttp.WithRedis(rdb))
	}

	client, err := embedded.New(coreCfg, pg, engineOpts...)
	if err != nil {
		return fmt.Errorf("build authkit engine: %w", err)
	}
	svc, err := authhttp.NewServer(client, httpOpts...)
	if err != nil {
		return fmt.Errorf("build authkit http server: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	// Downstream verifiers fetch signing keys here (public).
	mux.Handle("/.well-known/jwks.json", svc.JWKSHandler())

	// Browser-facing auth-flow routes under the configured prefix.
	apiH := svc.APIHandler()
	oidcH := svc.OIDCHandler()
	prefix := cfg.apiPrefix
	mux.Handle(prefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet &&
			strings.HasPrefix(r.URL.Path, prefix+"/oidc/") &&
			(strings.HasSuffix(r.URL.Path, "/login") || strings.HasSuffix(r.URL.Path, "/callback")) {
			http.StripPrefix(prefix, oidcH).ServeHTTP(w, r)
			return
		}
		http.StripPrefix(prefix, apiH).ServeHTTP(w, r)
	}))

	// Management API: provision/manage/mint, driven by the remote SDK or non-Go
	// clients. Gated by the app→server bearer token. Fail closed: with no token
	// configured we do NOT expose 93 management methods unauthenticated unless the
	// operator is explicitly in dev.
	if cfg.mgmtToken != "" {
		mux.Handle("/v1/call/", server.NewHandler(client, cfg.mgmtToken))
		log.Printf("management API enabled at /v1/call/ (bearer-authenticated)")
	} else if isDevEnv(cfg.env) {
		mux.Handle("/v1/call/", server.NewHandler(client, ""))
		log.Printf("WARNING: management API enabled UNAUTHENTICATED (dev only; set AUTHKIT_MGMT_TOKEN)")
	} else {
		log.Printf("management API DISABLED: set AUTHKIT_MGMT_TOKEN to enable it outside dev")
	}

	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("authkit-server listening on %s (issuer=%s, env=%s)", cfg.listenAddr, cfg.issuer, cfg.env)
	return httpServer.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isDevEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "", "dev", "development", "local", "test":
		return true
	}
	return false
}
