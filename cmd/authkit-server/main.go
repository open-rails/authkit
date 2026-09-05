// Command authkit-server is the dev/CI harness for AuthKit: the engine plus
// authhttp.MountHandler on one listener, with /healthz. AuthKit ships as an
// embedded library; this binary exists so the compose stack and CI can boot a
// migrated database and exercise the real HTTP surface.
//
// Subcommands: `serve` (default) runs the server; `migrate` applies the Postgres
// schema and exits (the same runner embedding hosts use). `serve` also migrates
// first when AUTHKIT_MIGRATE_ON_START=true. Config comes from env, read once
// here; the library reads none.
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
	"slices"
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
	"github.com/open-rails/migratekit"
)

type config struct {
	naming         authkit.NamingConfig
	listenAddr     string
	dbURL          string
	issuer         string
	audiences      []string
	keysPath       string
	schema         string
	env            string
	redisAddr      string
	redisURL       string
	redisPassword  string
	apiPrefix      string
	regVerify      string // registration verification policy: none|optional|required
	migrateOnStart bool   // run schema migrations before serving (CI/dev convenience)
	allowMemory    bool
	apiKeyPrefix   string // branded API-key prefix (APIKeysConfig.Prefix)
	// Standalone reachability knobs (#236): previously library-only options with
	// no env mapping, so a bare binary deployment could not set them.
	trustedProxies    []string      // CIDRs whose X-Forwarded-For is trusted (reverse proxy / LB)
	cloudflareProxies []string      // Cloudflare egress CIDRs; + CF-Connecting-IP fallback (ak#298)
	directPeerIP      bool          // assert no proxy in front; required posture in prod without proxy CIDRs (ak#299)
	accessTokenTTL    time.Duration // 0 => library default (15m)
	refreshTokenTTL   time.Duration // 0 => indefinite sessions
	sessionMaxPerUser int           // 0 => default 3; -1 => unlimited
	// 0 => default 30s; negative => strictly single-use rotation (ak#274).
	refreshRotationGrace time.Duration
	verifySendTimeout    time.Duration // per email/SMS send bound; 0 => 15s
	twoFAMode            string        // disabled|optional|required ("" => optional)
	twoFAMethods         []string      // subset of email,sms,totp ("" => all)
	passkeyRPID          string
	passkeyRPName        string
	passkeyOrigins       []string
	languages            []string // supported UI languages ("" => en-only)
	defaultLanguage      string
	bootstrapPath        string // startup-once bootstrap manifest (YAML); "" => none
	// Inline JWT key material (#231): the LIBRARY reads no env, so the binary
	// reads AUTHKIT_ACTIVE_KEY_ID / AUTHKIT_ACTIVE_PRIVATE_KEY_PEM /
	// AUTHKIT_PUBLIC_KEYS here — once, at the binary boundary — and passes an
	// explicit KeySource in.
	activeKeyID         string
	activePrivateKeyPEM string
	publicKeysPEM       map[string]string // kid -> public-key PEM (retired keys kept in JWKS)
}

func loadConfig() (*config, error) {
	dbURL, err := dbURLFromEnv()
	if err != nil {
		return nil, err
	}
	c := &config{
		listenAddr:     envOr("AUTHKIT_LISTEN_ADDR", ":8080"),
		dbURL:          dbURL,
		issuer:         strings.TrimRight(envOr("AUTHKIT_ISSUER", ""), "/"),
		audiences:      splitCSV(envOr("AUTHKIT_AUDIENCES", "authkit")),
		keysPath:       strings.TrimSpace(os.Getenv("AUTHKIT_KEYS_PATH")),
		schema:         strings.TrimSpace(os.Getenv("AUTHKIT_SCHEMA")),
		env:            envOr("AUTHKIT_ENV", "dev"),
		redisAddr:      strings.TrimSpace(os.Getenv("AUTHKIT_REDIS_ADDR")),
		redisURL:       strings.TrimSpace(os.Getenv("AUTHKIT_REDIS_URL")),
		redisPassword:  os.Getenv("AUTHKIT_REDIS_PASSWORD"),
		apiPrefix:      envOr("AUTHKIT_API_PREFIX", "/api/v1"),
		migrateOnStart: envBool("AUTHKIT_MIGRATE_ON_START", false),
		// #305: a non-dev boot without Redis refuses unless this explicit
		// single-instance opt-in is set.
		allowMemory:  envBool("AUTHKIT_ALLOW_MEMORY_EPHEMERAL", false),
		apiKeyPrefix: strings.TrimSpace(os.Getenv("AUTHKIT_API_KEY_PREFIX")),
		// Default to "none": a bare standalone server has no email/SMS sender, and
		// "required" verification with no sender is unsatisfiable. Operators set
		// this once they wire a sender (senders are an embedded.New option).
		regVerify:           strings.ToLower(envOr("AUTHKIT_REGISTRATION_VERIFICATION", "none")),
		activeKeyID:         strings.TrimSpace(os.Getenv("AUTHKIT_ACTIVE_KEY_ID")),
		activePrivateKeyPEM: strings.TrimSpace(os.Getenv("AUTHKIT_ACTIVE_PRIVATE_KEY_PEM")),
		trustedProxies:      splitCSV(os.Getenv("AUTHKIT_TRUSTED_PROXIES")),
		cloudflareProxies:   splitCSV(os.Getenv("AUTHKIT_CLOUDFLARE_PROXIES")),
		directPeerIP:        envBool("AUTHKIT_DIRECT_PEER_IP", false),
		twoFAMode:           strings.ToLower(strings.TrimSpace(os.Getenv("AUTHKIT_2FA_MODE"))),
		twoFAMethods:        splitCSV(strings.ToLower(os.Getenv("AUTHKIT_2FA_METHODS"))),
		passkeyRPID:         strings.TrimSpace(os.Getenv("AUTHKIT_PASSKEY_RPID")),
		passkeyRPName:       strings.TrimSpace(os.Getenv("AUTHKIT_PASSKEY_RP_DISPLAY_NAME")),
		passkeyOrigins:      splitCSV(os.Getenv("AUTHKIT_PASSKEY_ORIGINS")),
		languages:           splitCSV(strings.ToLower(os.Getenv("AUTHKIT_LANGUAGES"))),
		defaultLanguage:     strings.ToLower(strings.TrimSpace(os.Getenv("AUTHKIT_DEFAULT_LANGUAGE"))),
		bootstrapPath:       strings.TrimSpace(os.Getenv("AUTHKIT_BOOTSTRAP_PATH")),
	}
	if c.naming, err = namingConfigFromEnv(); err != nil {
		return nil, err
	}
	if c.issuer == "" {
		return nil, errors.New("AUTHKIT_ISSUER is required")
	}
	if c.dbURL == "" {
		return nil, errors.New("DB_URL (or DATABASE_URL) is required")
	}
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
	if c.refreshRotationGrace, err = envDuration("AUTHKIT_REFRESH_ROTATION_GRACE"); err != nil {
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
	if raw := strings.TrimSpace(os.Getenv("AUTHKIT_PUBLIC_KEYS")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.publicKeysPEM); err != nil {
			return nil, fmt.Errorf("parse AUTHKIT_PUBLIC_KEYS JSON (kid -> public-key PEM): %w", err)
		}
	}
	// #266: the one enum pair that skipped the house-style boot refusal. The
	// library quietly falls back to "en" when the effective default is outside
	// the supported set — refuse at boot instead of serving a language nobody
	// configured.
	if len(c.languages) > 0 || c.defaultLanguage != "" {
		supported := c.languages
		if len(supported) == 0 {
			supported = []string{"en"}
		}
		def := c.defaultLanguage
		if def == "" {
			def = "en"
		}
		if !slices.Contains(supported, def) {
			return nil, fmt.Errorf("AUTHKIT_DEFAULT_LANGUAGE %q is not in AUTHKIT_LANGUAGES %v (set it to one of the supported languages)", def, supported)
		}
	}
	return c, nil
}

// dbURLFromEnv resolves the Postgres DSN from DB_URL / DATABASE_URL. Setting
// both is a loud configuration error, not a silent precedence pick (#266 —
// same discipline as the AUTHKIT_REDIS_URL/AUTHKIT_REDIS_ADDR pair).
func dbURLFromEnv() (string, error) {
	dbURL := strings.TrimSpace(os.Getenv("DB_URL"))
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL != "" && databaseURL != "" {
		return "", errors.New("set DB_URL or DATABASE_URL, not both")
	}
	if dbURL == "" {
		dbURL = databaseURL
	}
	return dbURL, nil
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

	// #244: authenticated/TLS Redis. AUTHKIT_REDIS_URL takes the standard
	// redis:// / rediss:// form (password, TLS, and db number all ride in the
	// URL via redis.ParseURL); AUTHKIT_REDIS_ADDR (+ optional
	// AUTHKIT_REDIS_PASSWORD) remains for discrete-var deployments. Setting both
	// is a loud configuration error, not a silent precedence pick.
	var rdb *redis.Client
	switch {
	case cfg.redisURL != "" && cfg.redisAddr != "":
		return fmt.Errorf("set AUTHKIT_REDIS_URL or AUTHKIT_REDIS_ADDR, not both")
	case cfg.redisURL != "":
		opts, err := redis.ParseURL(cfg.redisURL)
		if err != nil {
			return fmt.Errorf("parse AUTHKIT_REDIS_URL: %w", err)
		}
		rdb = redis.NewClient(opts)
		defer func() { _ = rdb.Close() }()
	case cfg.redisAddr != "":
		rdb = redis.NewClient(&redis.Options{Addr: cfg.redisAddr, Password: cfg.redisPassword})
		defer func() { _ = rdb.Close() }()
	}

	// AUTHKIT_ENV (default "dev") is the binary's own switch: a dev-like value
	// turns on every explicit dev opt-in below; the library itself carries no
	// environment notion (#314). Only dev/development/local/test are dev;
	// everything else (incl. staging) is prod-like/fail-closed.
	devMode := isDevEnv(cfg.env)

	// Bootstrap manifest, loaded up front (#266): the dev fixture section feeds
	// engine options at construction; the seed sections are applied (apply-once)
	// after the engine is built. Dev fixtures in a non-dev env refuse to boot —
	// entitlements seeded into every token would be a billing bypass in prod.
	var manifest *authkit.BootstrapManifest
	if cfg.bootstrapPath != "" {
		m, err := embedded.LoadBootstrapManifestFile(cfg.bootstrapPath)
		if err != nil {
			return fmt.Errorf("load bootstrap manifest %s: %w", cfg.bootstrapPath, err)
		}
		manifest = &m
	}
	if manifest != nil && len(manifest.Dev.StaticEntitlements) > 0 && !devMode {
		return fmt.Errorf("bootstrap manifest %s sets dev.static_entitlements but AUTHKIT_ENV=%q is not a dev environment", cfg.bootstrapPath, cfg.env)
	}

	// Key resolution (#231): env is read ONLY here, at the binary boundary.
	// Inline env key material (AUTHKIT_ACTIVE_KEY_ID/AUTHKIT_ACTIVE_PRIVATE_KEY_PEM/
	// AUTHKIT_PUBLIC_KEYS) wins; otherwise the engine loads <keysPath>/keys.json,
	// and ONLY a dev env opts in to ephemeral generated keys. Prod with no keys
	// refuses to boot.
	keysCfg := embedded.KeysConfig{Path: cfg.keysPath, AllowEphemeralDevKeys: devMode}
	if cfg.activeKeyID != "" || cfg.activePrivateKeyPEM != "" {
		ks, err := jwtkit.NewStaticKeySourceFromPEM(cfg.activeKeyID, cfg.activePrivateKeyPEM, cfg.publicKeysPEM)
		if err != nil {
			return fmt.Errorf("load JWT keys from AUTHKIT_ACTIVE_KEY_ID/AUTHKIT_ACTIVE_PRIVATE_KEY_PEM: %w", err)
		}
		keysCfg = embedded.KeysConfig{Source: ks}
	}

	twoFAMethods := make([]authkit.TwoFactorMethod, 0, len(cfg.twoFAMethods))
	for _, m := range cfg.twoFAMethods {
		twoFAMethods = append(twoFAMethods, authkit.TwoFactorMethod(m))
	}

	coreCfg := embedded.Config{
		Naming:       cfg.naming,
		Schema:       cfg.schema,
		Ephemeral:    embedded.EphemeralConfig{AllowMemory: cfg.allowMemory || (devMode && rdb == nil)},
		Applications: embedded.ApplicationsConfig{AllowPrivateNetworkJWKS: devMode},
		Token: embedded.TokenConfig{
			Issuer:               cfg.issuer,
			IssuedAudiences:      cfg.audiences,
			ExpectedAudiences:    cfg.audiences,
			AccessTokenDuration:  cfg.accessTokenTTL,
			RefreshTokenDuration: cfg.refreshTokenTTL,
			SessionMaxPerUser:    cfg.sessionMaxPerUser,
			RefreshRotationGrace: cfg.refreshRotationGrace,
		},
		Keys: keysCfg,
		Registration: embedded.RegistrationConfig{
			Verification:            embedded.RegistrationVerificationPolicy(cfg.regVerify),
			VerificationSendTimeout: cfg.verifySendTimeout,
			AllowMissingSenders:     devMode,
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

	deps := embedded.Deps{Postgres: pg, Redis: rdb}
	var httpOpts []authhttp.Option
	if rdb != nil {
		httpOpts = append(httpOpts, authhttp.WithRedis(rdb))
	}
	if len(cfg.trustedProxies) > 0 {
		httpOpts = append(httpOpts, authhttp.WithTrustedProxies(cfg.trustedProxies...))
	}
	if len(cfg.cloudflareProxies) > 0 {
		httpOpts = append(httpOpts, authhttp.WithCloudflareProxies(cfg.cloudflareProxies...))
	}
	if cfg.directPeerIP || (devMode && len(cfg.trustedProxies) == 0 && len(cfg.cloudflareProxies) == 0) {
		httpOpts = append(httpOpts, authhttp.WithDirectPeerIP())
	}
	if len(cfg.languages) > 0 || cfg.defaultLanguage != "" {
		httpOpts = append(httpOpts, authhttp.WithLanguageConfig(authhttp.LanguageConfig{
			Supported: cfg.languages,
			Default:   cfg.defaultLanguage,
		}))
	}
	if devMode && manifest != nil && len(manifest.Dev.StaticEntitlements) > 0 {
		deps.Entitlements = staticDevEntitlements{names: manifest.Dev.StaticEntitlements}
	}

	client, err := embedded.New(coreCfg, deps)
	if err != nil {
		return fmt.Errorf("build authkit engine: %w", err)
	}

	// Startup-once bootstrap manifest (#236): seed initial users / remote apps
	// from a YAML file. Apply-once is DB-marked, so restarts are no-ops. A
	// fixtures-only manifest (just `dev:`) seeds nothing, so it skips the
	// apply — and with it the genesis non-empty-database refusal.
	if manifest != nil && (len(manifest.Users) > 0 || len(manifest.RemoteApplications) > 0) {
		res, err := client.ApplyBootstrapManifest(ctx, *manifest, authkit.BootstrapReconcileOptions{StartupOnly: true})
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

	// The whole auth surface — JWKS at root, browser OIDC at /oidc, API under
	// the configured prefix — is ONE neutral handler (#250).
	prefix := cfg.apiPrefix
	if strings.TrimSpace(prefix) == "" {
		prefix = "/" // explicit empty AUTHKIT_API_PREFIX means root
	}
	authH, err := authhttp.MountHandler(svc, authhttp.MountOptions{APIPrefix: prefix})
	if err != nil {
		return fmt.Errorf("mount authkit routes: %w", err)
	}
	mux.Handle("/", authH)

	// Daily auth-state sweep (expired sessions/invites + session-event
	// retention, #245). Embedding hosts schedule Client.CleanupExpiredAuthState
	// themselves; the standalone binary has no host scheduler, so it owns the tick.
	go func() {
		tick := time.NewTicker(24 * time.Hour)
		defer tick.Stop()
		for {
			if err := client.CleanupExpiredAuthState(ctx); err != nil {
				log.Printf("auth-state cleanup: %v", err)
			}
			<-tick.C
		}
	}()

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
	dbURL, err := dbURLFromEnv()
	if err != nil {
		return err
	}
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

// isDevEnv classifies AUTHKIT_ENV for this binary's dev opt-ins.
func isDevEnv(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "", "dev", "development", "local", "test":
		return true
	}
	return false
}

type staticDevEntitlements struct {
	names []string
}

func (p staticDevEntitlements) ListEntitlements(_ context.Context, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	for _, id := range userIDs {
		out[id] = append([]string(nil), p.names...)
	}
	return out, nil
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
