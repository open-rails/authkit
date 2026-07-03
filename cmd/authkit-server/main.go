// Command authkit-server is the standalone, self-hostable AuthKit server (#142).
// It runs the engine in-process and exposes, on one listener:
//
//   - the browser-facing auth-flow routes (register/login/OIDC/passwordless/…),
//   - the JWKS endpoint downstream verifiers fetch,
//   - the authenticated MANAGEMENT API (POST /v1/call/{Method}) that the
//     authkit/remote Go SDK and non-Go clients drive to provision/manage/mint.
//
// In a dev environment it ALSO serves the integration-test affordances that used
// to live in the now-deleted authkit-devserver (#194): GET {prefix}/dev/whoami
// (reflect the resolved principal) and, when AUTHKIT_DEV_MINT_SECRET is set,
// POST {prefix}/dev/mint (mint arbitrary access tokens). Both are mounted ONLY
// when AUTHKIT_ENV is a dev env — never reachable in production (fail-closed).
//
// Subcommands: `serve` (default) runs the server; `migrate` applies the Postgres
// schema and exits (the same runner embedding hosts use). `serve` also migrates
// first when AUTHKIT_MIGRATE_ON_START=true.
//
// A Go app swaps embedded↔remote with one construction line (embedded.New ↔
// remote.New); both satisfy authkit.Client. main is thin — config comes from env;
// the library does the work (etcd's embed.Config / etcdmain split).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	pgmigrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/open-rails/authkit/server"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/migratekit"
)

type config struct {
	listenAddr     string
	dbURL          string
	issuer         string
	audiences      []string
	keysPath       string
	schema         string
	env            string
	redisAddr      string
	mgmtToken      string // app→server bearer credential for the management API
	apiPrefix      string
	regVerify      string // registration verification policy: none|optional|required
	migrateOnStart bool   // run schema migrations before serving (CI/dev convenience)
	apiKeyPrefix   string // branded API-key prefix (APIKeysConfig.Prefix)
	// Standalone reachability knobs (#236): previously library-only options with
	// no env mapping, so a bare binary deployment could not set them.
	trustedProxies    []string      // CIDRs whose forwarded headers are trusted (CDN/reverse proxy)
	accessTokenTTL    time.Duration // 0 => library default (15m)
	refreshTokenTTL   time.Duration // 0 => indefinite sessions
	sessionMaxPerUser int           // 0 => default 3; -1 => unlimited
	verifySendTimeout time.Duration // per email/SMS send bound; 0 => 15s
	twoFAMode         string        // disabled|optional|required ("" => optional)
	twoFAMethods      []string      // subset of email,sms,totp ("" => all)
	passkeyRPID       string
	passkeyRPName     string
	passkeyOrigins    []string
	languages         []string // supported UI languages ("" => en-only)
	defaultLanguage   string
	bootstrapPath     string // startup-once bootstrap manifest (YAML); "" => none
	// Inline JWT key material (#231): the LIBRARY reads no env, so the binary
	// reads ACTIVE_KEY_ID / ACTIVE_PRIVATE_KEY_PEM / PUBLIC_KEYS here — once, at
	// the binary boundary — and passes an explicit KeySource in.
	activeKeyID         string
	activePrivateKeyPEM string
	publicKeysPEM       map[string]string // kid -> public-key PEM (retired keys kept in JWKS)
	// Dev-only integration-test knobs (honored only when env is a dev env, #194).
	devMintSecret      string   // enables POST {prefix}/dev/mint when set
	staticEntitlements []string // seeded into access tokens for billing/entitlement E2E
}

func loadConfig() (*config, error) {
	c := &config{
		listenAddr:     envOr("AUTHKIT_LISTEN_ADDR", ":8080"),
		dbURL:          firstEnv("DB_URL", "DATABASE_URL"),
		issuer:         strings.TrimRight(envOr("AUTHKIT_ISSUER", ""), "/"),
		audiences:      splitCSV(envOr("AUTHKIT_AUDIENCES", "authkit")),
		keysPath:       strings.TrimSpace(os.Getenv("AUTHKIT_KEYS_PATH")),
		schema:         strings.TrimSpace(os.Getenv("AUTHKIT_SCHEMA")),
		env:            envOr("AUTHKIT_ENV", "dev"),
		redisAddr:      strings.TrimSpace(os.Getenv("AUTHKIT_REDIS_ADDR")),
		mgmtToken:      strings.TrimSpace(os.Getenv("AUTHKIT_MGMT_TOKEN")),
		apiPrefix:      envOr("AUTHKIT_API_PREFIX", "/api/v1"),
		migrateOnStart: envBool("AUTHKIT_MIGRATE_ON_START", false),
		apiKeyPrefix:   strings.TrimSpace(os.Getenv("AUTHKIT_API_KEY_PREFIX")),
		// Default to "none": a bare standalone server has no email/SMS sender, and
		// "required" verification with no sender is unsatisfiable. Operators set
		// this once they wire a sender (senders are an embedded.New option).
		regVerify:           strings.ToLower(envOr("AUTHKIT_REGISTRATION_VERIFICATION", "none")),
		activeKeyID:         strings.TrimSpace(os.Getenv("ACTIVE_KEY_ID")),
		activePrivateKeyPEM: strings.TrimSpace(os.Getenv("ACTIVE_PRIVATE_KEY_PEM")),
		devMintSecret:       strings.TrimSpace(os.Getenv("AUTHKIT_DEV_MINT_SECRET")),
		staticEntitlements:  splitCSV(os.Getenv("AUTHKIT_STATIC_ENTITLEMENTS")),
		trustedProxies:      splitCSV(os.Getenv("AUTHKIT_TRUSTED_PROXIES")),
		twoFAMode:           strings.ToLower(strings.TrimSpace(os.Getenv("AUTHKIT_2FA_MODE"))),
		twoFAMethods:        splitCSV(strings.ToLower(os.Getenv("AUTHKIT_2FA_METHODS"))),
		passkeyRPID:         strings.TrimSpace(os.Getenv("AUTHKIT_PASSKEY_RPID")),
		passkeyRPName:       strings.TrimSpace(os.Getenv("AUTHKIT_PASSKEY_RP_DISPLAY_NAME")),
		passkeyOrigins:      splitCSV(os.Getenv("AUTHKIT_PASSKEY_ORIGINS")),
		languages:           splitCSV(strings.ToLower(os.Getenv("AUTHKIT_LANGUAGES"))),
		defaultLanguage:     strings.ToLower(strings.TrimSpace(os.Getenv("AUTHKIT_DEFAULT_LANGUAGE"))),
		bootstrapPath:       strings.TrimSpace(os.Getenv("AUTHKIT_BOOTSTRAP_PATH")),
	}
	if c.issuer == "" {
		return nil, errors.New("AUTHKIT_ISSUER is required")
	}
	if c.dbURL == "" {
		return nil, errors.New("DB_URL (or DATABASE_URL) is required")
	}
	var err error
	if c.accessTokenTTL, err = envDuration("AUTHKIT_ACCESS_TOKEN_TTL"); err != nil {
		return nil, err
	}
	if c.refreshTokenTTL, err = envDuration("AUTHKIT_REFRESH_TOKEN_TTL"); err != nil {
		return nil, err
	}
	if c.verifySendTimeout, err = envDuration("AUTHKIT_VERIFICATION_SEND_TIMEOUT"); err != nil {
		return nil, err
	}
	if c.sessionMaxPerUser, err = envInt("AUTHKIT_SESSION_MAX_PER_USER"); err != nil {
		return nil, err
	}
	switch c.twoFAMode {
	case "", "disabled", "optional", "required":
	default:
		return nil, fmt.Errorf("invalid AUTHKIT_2FA_MODE %q (want disabled|optional|required)", c.twoFAMode)
	}
	for _, m := range c.twoFAMethods {
		switch m {
		case "email", "sms", "totp":
		default:
			return nil, fmt.Errorf("invalid AUTHKIT_2FA_METHODS entry %q (want a comma-separated subset of email,sms,totp)", m)
		}
	}
	if raw := strings.TrimSpace(os.Getenv("PUBLIC_KEYS")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.publicKeysPEM); err != nil {
			return nil, fmt.Errorf("parse PUBLIC_KEYS JSON (kid -> public-key PEM): %w", err)
		}
	}
	return c, nil
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		cmd = strings.TrimSpace(os.Args[1])
	}
	switch cmd {
	case "serve":
		if err := run(); err != nil {
			log.Fatalf("authkit-server: %v", err)
		}
	case "migrate":
		if err := runMigrateCmd(); err != nil {
			log.Fatalf("authkit-server: %v", err)
		}
	default:
		log.Fatalf("authkit-server: unknown command %q (supported: serve, migrate)", cmd)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()

	if cfg.migrateOnStart {
		if err := runMigrations(ctx, cfg.dbURL); err != nil {
			return err
		}
	}

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

	// ONE dev/prod classifier (#231): AUTHKIT_ENV (default "dev" via envOr) maps
	// through embedded.IsDevEnvironment — only dev/development/local/test are
	// dev; everything else (incl. staging) is prod-like/fail-closed.
	devMode := embedded.IsDevEnvironment(cfg.env)

	// Key resolution (#231): env is read ONLY here, at the binary boundary.
	// Inline env key material (ACTIVE_KEY_ID/ACTIVE_PRIVATE_KEY_PEM/PUBLIC_KEYS)
	// wins; otherwise the engine loads <keysPath>/keys.json, and ONLY a dev env
	// opts in to ephemeral generated keys. Prod with no keys refuses to boot.
	keysCfg := embedded.KeysConfig{Path: cfg.keysPath, AllowEphemeralDevKeys: devMode}
	if cfg.activeKeyID != "" || cfg.activePrivateKeyPEM != "" {
		ks, err := jwtkit.NewStaticKeySourceFromPEM(cfg.activeKeyID, cfg.activePrivateKeyPEM, cfg.publicKeysPEM)
		if err != nil {
			return fmt.Errorf("load JWT keys from ACTIVE_KEY_ID/ACTIVE_PRIVATE_KEY_PEM: %w", err)
		}
		keysCfg = embedded.KeysConfig{Source: ks}
	}

	// /dev/mint signs arbitrary tokens, so it needs the active signer handle. Build
	// an explicit key source (same file→generated precedence the engine uses) and
	// hand it to the engine so JWKS and dev-mint share one active key. Only in
	// dev with a mint secret; the prod path keeps Keys.Path resolution untouched.
	var devSigner jwtkit.Signer
	if devMode && cfg.devMintSecret != "" {
		if keysCfg.Source == nil {
			ks, err := jwtkit.ResolveKeySource(cfg.keysPath, true)
			if err != nil {
				return fmt.Errorf("load jwt keys for dev mint: %w", err)
			}
			keysCfg = embedded.KeysConfig{Source: ks}
		}
		devSigner = keysCfg.Source.ActiveSigner()
	}

	twoFAMethods := make([]authkit.TwoFactorMethod, 0, len(cfg.twoFAMethods))
	for _, m := range cfg.twoFAMethods {
		twoFAMethods = append(twoFAMethods, authkit.TwoFactorMethod(m))
	}

	coreCfg := embedded.Config{
		Environment: cfg.env,
		Schema:      cfg.schema,
		Token: embedded.TokenConfig{
			Issuer:               cfg.issuer,
			IssuedAudiences:      cfg.audiences,
			ExpectedAudiences:    cfg.audiences,
			AccessTokenDuration:  cfg.accessTokenTTL,
			RefreshTokenDuration: cfg.refreshTokenTTL,
			SessionMaxPerUser:    cfg.sessionMaxPerUser,
		},
		Keys: keysCfg,
		Registration: embedded.RegistrationConfig{
			Verification:            embedded.RegistrationVerificationPolicy(cfg.regVerify),
			VerificationSendTimeout: cfg.verifySendTimeout,
		},
		APIKeys: embedded.APIKeysConfig{Prefix: cfg.apiKeyPrefix},
		TwoFactor: embedded.TwoFactorConfig{
			Mode:    authkit.TwoFactorMode(cfg.twoFAMode),
			Methods: twoFAMethods,
		},
		Passkeys: embedded.PasskeyConfig{
			RPID:          cfg.passkeyRPID,
			RPDisplayName: cfg.passkeyRPName,
			Origins:       cfg.passkeyOrigins,
		},
	}

	var engineOpts []embedded.Option
	var httpOpts []authhttp.Option
	if rdb != nil {
		engineOpts = append(engineOpts, embedded.WithRedis(rdb))
		httpOpts = append(httpOpts, authhttp.WithRedis(rdb))
	}
	if len(cfg.trustedProxies) > 0 {
		httpOpts = append(httpOpts, authhttp.WithTrustedProxies(cfg.trustedProxies...))
	}
	if len(cfg.languages) > 0 || cfg.defaultLanguage != "" {
		httpOpts = append(httpOpts, authhttp.WithLanguageConfig(authhttp.LanguageConfig{
			Supported: cfg.languages,
			Default:   cfg.defaultLanguage,
		}))
	}
	if devMode && len(cfg.staticEntitlements) > 0 {
		engineOpts = append(engineOpts, embedded.WithEntitlements(staticDevEntitlements{names: cfg.staticEntitlements}))
	}

	client, err := embedded.New(coreCfg, pg, engineOpts...)
	if err != nil {
		return fmt.Errorf("build authkit engine: %w", err)
	}

	// Startup-once bootstrap manifest (#236): seed initial users / remote apps
	// from a YAML file. Apply-once is DB-marked, so restarts are no-ops.
	if cfg.bootstrapPath != "" {
		manifest, err := embedded.LoadBootstrapManifestFile(cfg.bootstrapPath)
		if err != nil {
			return fmt.Errorf("load bootstrap manifest %s: %w", cfg.bootstrapPath, err)
		}
		res, err := client.ApplyBootstrapManifest(ctx, manifest, authkit.BootstrapReconcileOptions{StartupOnly: true})
		if err != nil {
			return fmt.Errorf("apply bootstrap manifest %s: %w", cfg.bootstrapPath, err)
		}
		if res.AlreadyApplied {
			log.Printf("bootstrap manifest %s already applied; skipped", cfg.bootstrapPath)
		} else {
			log.Printf("bootstrap manifest %s applied: users_created=%d passwords_set=%d root_roles=%d remote_apps=%d",
				cfg.bootstrapPath, res.UsersCreated, res.PasswordsSet, res.RootRoleAssignments, res.RemoteApplications)
		}
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

	// Dev-only integration-test affordances, consolidated from the former
	// authkit-devserver (#194). Mounted ONLY in a dev env; /dev/mint additionally
	// requires AUTHKIT_DEV_MINT_SECRET. Fail-closed: prod or no secret ⇒ absent.
	var devMintH, devWhoamiH http.Handler
	if devMode {
		devWhoamiH = devWhoamiHandler(svc)
		if devSigner != nil {
			devMintH = devMintHandler(cfg.issuer, devSigner, cfg.devMintSecret)
			log.Printf("dev endpoints enabled: GET %s/dev/whoami, POST %s/dev/mint (DEV ONLY)", prefix, prefix)
		} else {
			log.Printf("dev endpoint enabled: GET %s/dev/whoami (DEV ONLY; set AUTHKIT_DEV_MINT_SECRET to enable /dev/mint)", prefix)
		}
	}

	mux.Handle(prefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if devMintH != nil && r.Method == http.MethodPost && r.URL.Path == prefix+"/dev/mint" {
			devMintH.ServeHTTP(w, r)
			return
		}
		if devWhoamiH != nil && r.Method == http.MethodGet && r.URL.Path == prefix+"/dev/whoami" {
			devWhoamiH.ServeHTTP(w, r)
			return
		}
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
	} else if devMode {
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

// runMigrateCmd applies the Postgres schema and exits. It needs only the DB DSN
// (no issuer/keys), so prod can run it as a one-shot job separate from serving.
func runMigrateCmd() error {
	dbURL := firstEnv("DB_URL", "DATABASE_URL")
	if dbURL == "" {
		return errors.New("DB_URL (or DATABASE_URL) is required")
	}
	if err := runMigrations(context.Background(), dbURL); err != nil {
		return err
	}
	log.Printf("authkit-server: migrations applied")
	return nil
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

	// Same runner embedding hosts use: migratekit, name-tracked per app in
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

// --- Dev-only test affordances (consolidated from authkit-devserver, #194) ---

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

type staticDevEntitlements struct {
	names []string
}

func (p staticDevEntitlements) ListEntitlements(context.Context, string) ([]string, error) {
	return append([]string(nil), p.names...), nil
}

// devWhoamiHandler reflects the authenticated principal as resolved by the real
// verifier (JWT user OR branded API key), behind the standard auth middleware.
// Dev-only; used by the RBAC E2E suite to assert API-key resolution.
func devWhoamiHandler(svc *authhttp.Service) http.Handler {
	reflect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"permissions": cl.Permissions,
			"is_api_key":  cl.PrincipalKind() == authkit.PrincipalKindAPIKey,
			"user_id":     cl.UserID,
		})
	})
	return verify.Required(svc.Verifier())(reflect)
}

// devMintHandler mints arbitrary access tokens for downstream-service E2E tests.
// Dev-only and shared-secret gated; never mounted outside a dev env.
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

		token, err := jwtkit.SignWithType(r.Context(), signer, claims, jwtkit.AccessTokenType, true)
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

func envDuration(key string) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration in %s=%q (want a Go duration like 15m, 720h): %w", key, raw, err)
	}
	return d, nil
}

func envInt(key string) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid integer in %s=%q: %w", key, raw, err)
	}
	return n, nil
}

func envBool(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("invalid boolean in %s=%q; using default %t", key, raw, def)
		return def
	}
	return b
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
