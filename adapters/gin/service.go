package authgin

import (
	"log"
	"time"

	"github.com/PaulFidika/authkit/adapters/gin/handlers"
	"github.com/PaulFidika/authkit/adapters/ginutil"
	core "github.com/PaulFidika/authkit/core"
	oidckit "github.com/PaulFidika/authkit/oidc"
	memorylimiter "github.com/PaulFidika/authkit/ratelimit/memory"
	redisl "github.com/PaulFidika/authkit/ratelimit/redis"
	"github.com/PaulFidika/authkit/siws"
	memorystore "github.com/PaulFidika/authkit/storage/memory"
	redisstore "github.com/PaulFidika/authkit/storage/redis"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Service wraps core.Service with HTTP mounting and email helpers.
type Service struct {
	svc           *core.Service
	rd            *redis.Client
	rl            ginutil.RateLimiter
	oidcProviders map[string]oidckit.RPConfig
	solanaDomain  string // Domain for SIWS messages (optional, derived from request if empty)
	langCfg       *LanguageConfig
}

// NewService constructs a core.Service and wraps it for HTTP mounting.
// Returns an error if the core service fails to initialize (e.g., missing keys in production).
func NewService(cfg core.Config) (*Service, error) {
	coreSvc, err := core.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	prov := cfg.Providers
	// Default to in-memory ephemeral store for dev/single-instance use.
	coreSvc = coreSvc.WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory)
	s := &Service{svc: coreSvc, oidcProviders: prov}
	return s, nil
}

func (s *Service) WithPostgres(pg *pgxpool.Pool) *Service { s.svc = s.svc.WithPostgres(pg); return s }
func (s *Service) WithEntitlements(p core.EntitlementsProvider) *Service {
	s.svc = s.svc.WithEntitlements(p)
	return s
}
func (s *Service) WithRedis(rd *redis.Client) *Service {
	s.rd = rd
	if rd != nil {
		s.svc = s.svc.WithEphemeralStore(redisstore.NewKV(rd), core.EphemeralRedis)
	}
	return s
}
func (s *Service) WithRateLimiter(rl ginutil.RateLimiter) *Service { s.rl = rl; return s }
func (s *Service) WithEmailSender(es core.EmailSender) *Service {
	s.svc = s.svc.WithEmailSender(es)
	return s
}

func (s *Service) WithSMSSender(sender core.SMSSender) *Service {
	s.svc = s.svc.WithSMSSender(sender)
	return s
}

func (s *Service) WithLanguageConfig(cfg LanguageConfig) *Service {
	s.langCfg = &cfg
	return s
}

// WithAuthLogger wires a custom authentication event logger (e.g., ClickHouse sink).
func (s *Service) WithAuthLogger(l core.AuthEventLogger) *Service {
	s.svc = s.svc.WithAuthLogger(l)
	return s
}

func (s *Service) WithEphemeralStore(store core.EphemeralStore, mode core.EphemeralMode) *Service {
	s.svc = s.svc.WithEphemeralStore(store, mode)
	return s
}

// WithSolanaDomain sets the domain used in SIWS sign-in messages.
// If not set, the domain is derived from the request Origin or Host header.
func (s *Service) WithSolanaDomain(domain string) *Service {
	s.solanaDomain = domain
	return s
}

// (No job wiring here.) The Gin service is HTTP-only.

// RegisterGin mounts all authkit routes on the provided router or group.
// Pass a prefixed group (e.g., r.Group("/api/v1")) to mount under a prefix.
// GinRegisterJWKS mounts the JWKS endpoint at the absolute root path.
func (s *Service) GinRegisterJWKS(root gin.IRouter) *Service {
	root.GET("/.well-known/jwks.json", handlers.HandleJWKS(s.svc))
	return s
}

// GinRegisterOIDC mounts browser redirect flows. By default these go under "/auth/...".
// GinRegisterOIDC mounts browser redirect flows. Optionally specify a site name for tracking.
func (s *Service) GinRegisterOIDC(root gin.IRouter, site ...string) *Service {
	rl := s.ensureLimiter()
	_ = rl // currently used inside handlers; keep initialized for rate limits
	providers := s.oidcProviders
	if providers == nil {
		providers = map[string]oidckit.RPConfig{}
	}
	mgr := oidckit.NewManagerFromMinimal(providers)
	state := s.stateCache()
	oidcCfg := handlers.OIDCConfig{Manager: mgr, StateCache: state}
	var siteName string
	if len(site) > 0 {
		siteName = site[0]
	}
	r := root.Group("")
	r.Use(LanguageMiddleware(s.langCfg))
	r.GET("/auth/oidc/:provider/login", handlers.HandleOIDCLoginGET(oidcCfg, s.svc, rl, siteName))
	r.GET("/auth/oidc/:provider/callback", handlers.HandleOIDCCallbackGET(oidcCfg, s.svc, nil, rl, siteName))
	if _, ok := providers["discord"]; ok {
		r.GET("/auth/oauth/discord/login", handlers.HandleDiscordLoginGET(oidcCfg, s.svc, rl))
		r.GET("/auth/oauth/discord/callback", handlers.HandleDiscordCallbackGET(oidcCfg, s.svc, rl, siteName))
	}
	return s
}

// GinRegisterAPI mounts JSON API endpoints under the given router/group (e.g., /api/v1).
// GinRegisterAPI mounts JSON API endpoints. Optionally specify a site name for tracking.
func (s *Service) GinRegisterAPI(api gin.IRouter, site ...string) *Service {
	rl := s.ensureLimiter()
	auth := MiddlewareFromSVC(s)
	r := api.Group("")
	r.Use(LanguageMiddleware(s.langCfg))
	if !core.IsDevEnvironment() {
		mode := s.svc.EphemeralMode()
		if mode != core.EphemeralRedis {
			panic("authkit: redis-compatible ephemeral store is required in production")
		}
	}

	var siteName string
	if len(site) > 0 {
		siteName = site[0]
	}

	r.POST("/auth/password/login", handlers.HandlePasswordLoginPOST(s.svc, rl, siteName))

	// Unified registration (accepts email or phone in identifier field)
	r.POST("/auth/register", handlers.HandleRegisterUnifiedPOST(s.svc, rl))
	r.POST("/auth/register/resend-email", handlers.HandlePendingRegistrationResendPOST(s.svc, rl))
	r.POST("/auth/register/resend-phone", handlers.HandlePhoneRegisterResendPOST(s.svc, rl))

	// Email-based password reset and verification
	r.POST("/auth/password/reset/request", handlers.HandlePasswordResetRequestPOST(s.svc, rl))
	r.POST("/auth/password/reset/confirm", handlers.HandlePasswordResetConfirmPOST(s.svc, rl))
	r.POST("/auth/password/reset/confirm-link", handlers.HandlePasswordResetConfirmLinkPOST(s.svc, rl))
	r.POST("/auth/email/verify/request", handlers.HandleEmailVerifyRequestPOST(s.svc, rl))
	r.POST("/auth/email/verify/confirm", handlers.HandleEmailVerifyConfirmPOST(s.svc, rl))
	r.POST("/auth/email/verify/confirm-link", handlers.HandleEmailVerifyConfirmLinkPOST(s.svc, rl))

	// Phone-based password reset and verification
	r.POST("/auth/phone/verify/request", handlers.HandlePhoneVerifyRequestPOST(s.svc, rl))
	r.POST("/auth/phone/verify/confirm", handlers.HandlePhoneVerifyConfirmPOST(s.svc, rl))
	r.POST("/auth/phone/password/reset/request", handlers.HandlePhonePasswordResetRequestPOST(s.svc, rl))
	r.POST("/auth/phone/password/reset/confirm", handlers.HandlePhonePasswordResetConfirmPOST(s.svc, rl))

	// Provider link start (OIDC)
	providers := s.oidcProviders
	if providers == nil {
		providers = map[string]oidckit.RPConfig{}
	}
	mgr := oidckit.NewManagerFromMinimal(providers)
	state := s.stateCache()
	oidcCfg := handlers.OIDCConfig{Manager: mgr, StateCache: state}
	r.POST("/auth/oidc/:provider/link/start", auth.Required(), handlers.HandleOIDCLinkStartPOST(oidcCfg, s.svc, rl))
	// Discord link start (OAuth2)
	if _, ok := providers["discord"]; ok {
		r.POST("/auth/oauth/discord/link/start", auth.Required(), handlers.HandleDiscordLinkStartPOST(oidcCfg, s.svc, rl))
	}

	// Sessions + logout
	r.POST("/auth/token", handlers.HandleAuthTokenPOST(s.svc, rl))
	r.POST("/auth/user/password", auth.Required(), handlers.HandleUserPasswordPOST(s.svc, rl))

	r.POST("/auth/sessions/current", handlers.HandleAuthSessionsCurrentPOST(s.svc, rl))
	r.GET("/auth/user/sessions", auth.Required(), handlers.HandleUserSessionsGET(s.svc, rl))
	r.DELETE("/auth/user/sessions/:id", auth.Required(), handlers.HandleUserSessionDELETE(s.svc, rl))
	r.DELETE("/auth/user/sessions", auth.Required(), handlers.HandleUserSessionsDELETE(s.svc, rl))

	r.DELETE("/auth/logout", auth.Required(), handlers.HandleLogoutDELETE(s.svc, rl))

	// User routes
	r.GET("/auth/user/me", auth.Required(), LookupDBUser(s.svc.Postgres()), handlers.HandleUserMeGET(s.svc, rl))
	r.PATCH("/auth/user/username", auth.Required(), handlers.HandleUserUsernamePATCH(s.svc, rl))
	r.POST("/auth/user/email/change/request", auth.Required(), handlers.HandleUserEmailChangeRequestPOST(s.svc, rl))
	r.POST("/auth/user/email/change/confirm", auth.Required(), handlers.HandleUserEmailChangeConfirmPOST(s.svc, rl))
	r.POST("/auth/user/email/change/resend", auth.Required(), handlers.HandleUserEmailChangeResendPOST(s.svc, rl))

	// Phone number change endpoints
	r.POST("/auth/user/phone/change/request", auth.Required(), handlers.HandleUserPhoneChangeRequestPOST(s.svc, rl))
	r.POST("/auth/user/phone/change/confirm", auth.Required(), handlers.HandleUserPhoneChangeConfirmPOST(s.svc, rl))
	r.POST("/auth/user/phone/change/resend", auth.Required(), handlers.HandleUserPhoneChangeResendPOST(s.svc, rl))

	r.PATCH("/auth/user/biography", auth.Required(), handlers.HandleUserBiographyPATCH(s.svc))
	r.DELETE("/auth/user", auth.Required(), handlers.HandleUserDeleteDELETE(s.svc, rl))
	r.DELETE("/auth/user/providers/:provider", auth.Required(), handlers.HandleUserUnlinkProviderDELETE(s.svc, rl))

	// Two-Factor Authentication routes
	r.GET("/auth/user/2fa", auth.Required(), handlers.HandleUser2FAStatusGET(s.svc, rl))

	r.POST("/auth/user/2fa/start-phone", auth.Required(), handlers.HandleUser2FAStartPhonePOST(s.svc, rl))
	r.POST("/auth/user/2fa/enable", auth.Required(), handlers.HandleUser2FAEnablePOST(s.svc, rl))
	r.POST("/auth/user/2fa/disable", auth.Required(), handlers.HandleUser2FADisablePOST(s.svc, rl))
	r.POST("/auth/user/2fa/regenerate-codes", auth.Required(), handlers.HandleUser2FARegenerateCodesPOST(s.svc, rl))
	r.POST("/auth/2fa/verify", handlers.HandleUser2FAVerifyPOST(s.svc, rl, siteName)) // No auth required - this is during login

	// Admin routes
	admin := r.Group("/auth/admin").Use(auth.Required(), auth.RequireAdmin(s.svc.Postgres()))
	admin.POST("/roles/grant", handlers.HandleAdminRolesGrantPOST(s.svc, rl))
	admin.POST("/roles/revoke", handlers.HandleAdminRolesRevokePOST(s.svc, rl))
	admin.GET("/users", handlers.HandleAdminUsersListGET(s.svc, rl))
	admin.GET("/users/:user_id", handlers.HandleAdminUserGET(s.svc))
	admin.POST("/users/ban", handlers.HandleAdminUsersBanPOST(s.svc, rl))
	admin.POST("/users/unban", handlers.HandleAdminUsersUnbanPOST(s.svc, rl))
	admin.POST("/users/set-email", handlers.HandleAdminUsersSetEmailPOST(s.svc, rl))
	admin.POST("/users/set-username", handlers.HandleAdminUsersSetUsernamePOST(s.svc, rl))
	admin.POST("/users/set-password", handlers.HandleAdminUsersSetPasswordPOST(s.svc, rl))

	admin.POST("/users/toggle-active", handlers.HandleAdminUserToggleActivePOST(s.svc, rl))

	admin.DELETE("/users/:user_id", handlers.HandleAdminUserDeleteDELETE(s.svc, rl))
	admin.POST("/users/:user_id/restore", handlers.HandleAdminUserRestorePOST(s.svc, rl))
	admin.GET("/users/deleted", handlers.HandleAdminDeletedUsersListGET(s.svc))

	// Solana SIWS authentication routes
	siwsCfg := handlers.SIWSConfig{
		Cache:  s.siwsCache(),
		Domain: s.solanaDomain,
	}
	r.POST("/auth/solana/challenge", handlers.HandleSolanaChallengePost(siwsCfg, s.svc, rl))
	r.POST("/auth/solana/login", handlers.HandleSolanaLoginPost(siwsCfg, s.svc, rl))
	r.POST("/auth/solana/link", auth.Required(), handlers.HandleSolanaLinkPost(siwsCfg, s.svc, rl))

	return s
}

// Deprecated: single-call registration. Prefer GinRegisterJWKS + GinRegisterOIDC + GinRegisterAPI.
func (s *Service) RegisterGin(r gin.IRouter) *Service {
	return s.GinRegisterJWKS(r).GinRegisterOIDC(r).GinRegisterAPI(r)
}

func (s *Service) Core() *core.Service { return s.svc }

func (s *Service) stateCache() oidckit.StateCache {
	if s.rd != nil {
		return redisstore.NewStateCache(s.rd, "auth:oidc:state:", 0)
	}
	return memorystore.NewStateCache(15 * time.Minute)
}

func (s *Service) siwsCache() siws.ChallengeCache {
	if s.rd != nil {
		return redisstore.NewSIWSCache(s.rd, "auth:siws:nonce:", 15*time.Minute)
	}
	return memorystore.NewSIWSCache(15 * time.Minute)
}

func (s *Service) ensureLimiter() ginutil.RateLimiter {
	if s.rl != nil {
		return s.rl
	}
	if s.rd != nil {
		return redisl.New(s.rd, defaultLimits())
	}
	// Fallback: in-memory rate limiter for single-node deployments when Redis
	// is unavailable. This provides basic protection without cross-node sharing.
	log.Printf("authkit: Redis client not configured; using in-memory rate limiter (single-node only)")
	return memorylimiter.New(defaultMemoryLimits())
}

// defaultLimits provides sensible default rate limits for auth endpoints.
func defaultLimits() map[string]redisl.Limit {

	return map[string]redisl.Limit{
		"default": {Limit: 120, Window: time.Minute},
		// 2FA-specific
		ginutil.RL2FAStartPhone:           {Limit: 3, Window: 10 * time.Minute},  // 3 requests per 10 min (SMS is costly)
		ginutil.RL2FAEnable:               {Limit: 6, Window: time.Hour},         // 6 enable attempts per hour
		ginutil.RL2FADisable:              {Limit: 6, Window: time.Hour},         // 6 disable attempts per hour
		ginutil.RL2FARegenerateCodes:      {Limit: 3, Window: time.Hour},         // 3 regenerations per hour
		ginutil.RL2FAVerify:               {Limit: 10, Window: 10 * time.Minute}, // 10 verifications per 10 min
		ginutil.RLAuthToken:               {Limit: 30, Window: time.Minute},
		ginutil.RLAuthRegister:            {Limit: 10, Window: time.Hour},
		ginutil.RLAuthRegisterResendEmail: {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthRegisterResendPhone: {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthLogout:              {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLPasswordLogin:           {Limit: 20, Window: time.Hour},
		ginutil.RLPasswordResetRequest:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLPasswordResetConfirm:    {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyRequest:      {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyConfirm:      {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLPhoneVerifyRequest:      {Limit: 3, Window: 10 * time.Minute}, // SMS is costly - 3/10min, ~6/hour
		// Phone change endpoints
		ginutil.RLUserPhoneChangeRequest:     {Limit: 3, Window: 10 * time.Minute},  // 3 requests per 10 min
		ginutil.RLUserPhoneChangeConfirm:     {Limit: 10, Window: 10 * time.Minute}, // 10 confirmations per 10 min
		ginutil.RLUserPhoneChangeResend:      {Limit: 3, Window: 10 * time.Minute},  // 3 resends per 10 min
		ginutil.RLAuthSessionsCurrent:        {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLAuthSessionsList:           {Limit: 120, Window: time.Minute},
		ginutil.RLAuthSessionsRevoke:         {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLAuthSessionsRevokeAll:      {Limit: 20, Window: time.Hour},
		ginutil.RLOIDCStart:                  {Limit: 30, Window: 10 * time.Minute},
		ginutil.RLOIDCCallback:               {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLUserMe:                     {Limit: 120, Window: time.Minute},
		ginutil.RLUserUpdateUsername:         {Limit: 12, Window: time.Hour},
		ginutil.RLUserUpdateEmail:            {Limit: 12, Window: time.Hour},
		ginutil.RLUserEmailChangeRequest:     {Limit: 6, Window: time.Hour},
		ginutil.RLUserEmailChangeConfirm:     {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLUserEmailChangeResend:      {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLUserDelete:                 {Limit: 6, Window: time.Hour},
		ginutil.RLUserUnlinkProvider:         {Limit: 12, Window: time.Hour},
		ginutil.RLUserPasswordChange:         {Limit: 6, Window: time.Hour},
		ginutil.RLAdminRolesGrant:            {Limit: 30, Window: time.Hour},
		ginutil.RLAdminRolesRevoke:           {Limit: 30, Window: time.Hour},
		ginutil.RLAdminUserSessionsList:      {Limit: 600, Window: time.Hour},
		ginutil.RLAdminUserSessionsRevoke:    {Limit: 60, Window: time.Hour},
		ginutil.RLAdminUserSessionsRevokeAll: {Limit: 30, Window: time.Hour},
		// Solana SIWS
		ginutil.RLSolanaChallenge: {Limit: 30, Window: 10 * time.Minute},
		ginutil.RLSolanaLogin:     {Limit: 20, Window: 10 * time.Minute},
		ginutil.RLSolanaLink:      {Limit: 12, Window: time.Hour},
	}
}

// defaultMemoryLimits mirrors defaultLimits but for the in-memory limiter type.
func defaultMemoryLimits() map[string]memorylimiter.Limit {
	return map[string]memorylimiter.Limit{
		"default": {Limit: 120, Window: time.Minute},
		// 2FA-specific
		ginutil.RL2FAStartPhone:      {Limit: 3, Window: 10 * time.Minute},  // 3 requests per 10 min (SMS is costly)
		ginutil.RL2FAEnable:          {Limit: 6, Window: time.Hour},         // 6 enable attempts per hour
		ginutil.RL2FADisable:         {Limit: 6, Window: time.Hour},         // 6 disable attempts per hour
		ginutil.RL2FARegenerateCodes: {Limit: 3, Window: time.Hour},         // 3 regenerations per hour
		ginutil.RL2FAVerify:          {Limit: 10, Window: 10 * time.Minute}, // 10 verifications per 10 min

		ginutil.RLAuthToken:               {Limit: 30, Window: time.Minute},
		ginutil.RLAuthRegister:            {Limit: 10, Window: time.Hour},
		ginutil.RLAuthRegisterResendEmail: {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthRegisterResendPhone: {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthLogout:              {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLPasswordLogin:           {Limit: 20, Window: time.Hour},
		ginutil.RLPasswordResetRequest:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLPasswordResetConfirm:    {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyRequest:      {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyConfirm:      {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLPhoneVerifyRequest:      {Limit: 3, Window: 10 * time.Minute}, // SMS is costly - 3/10min, ~6/hour
		// Phone change endpoints
		ginutil.RLUserPhoneChangeRequest:     {Limit: 3, Window: 10 * time.Minute},  // 3 requests per 10 min
		ginutil.RLUserPhoneChangeConfirm:     {Limit: 10, Window: 10 * time.Minute}, // 10 confirmations per 10 min
		ginutil.RLUserPhoneChangeResend:      {Limit: 3, Window: 10 * time.Minute},  // 3 resends per 10 min
		ginutil.RLAuthSessionsCurrent:        {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLAuthSessionsList:           {Limit: 120, Window: time.Minute},
		ginutil.RLAuthSessionsRevoke:         {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLAuthSessionsRevokeAll:      {Limit: 20, Window: time.Hour},
		ginutil.RLOIDCStart:                  {Limit: 30, Window: 10 * time.Minute},
		ginutil.RLOIDCCallback:               {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLUserMe:                     {Limit: 120, Window: time.Minute},
		ginutil.RLUserUpdateUsername:         {Limit: 12, Window: time.Hour},
		ginutil.RLUserUpdateEmail:            {Limit: 12, Window: time.Hour},
		ginutil.RLUserEmailChangeRequest:     {Limit: 6, Window: time.Hour},
		ginutil.RLUserEmailChangeConfirm:     {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLUserEmailChangeResend:      {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLUserDelete:                 {Limit: 6, Window: time.Hour},
		ginutil.RLUserUnlinkProvider:         {Limit: 12, Window: time.Hour},
		ginutil.RLUserPasswordChange:         {Limit: 6, Window: time.Hour},
		ginutil.RLAdminRolesGrant:            {Limit: 30, Window: time.Hour},
		ginutil.RLAdminRolesRevoke:           {Limit: 30, Window: time.Hour},
		ginutil.RLAdminUserSessionsList:      {Limit: 600, Window: time.Hour},
		ginutil.RLAdminUserSessionsRevoke:    {Limit: 60, Window: time.Hour},
		ginutil.RLAdminUserSessionsRevokeAll: {Limit: 30, Window: time.Hour},
		// Solana SIWS
		ginutil.RLSolanaChallenge: {Limit: 30, Window: 10 * time.Minute},
		ginutil.RLSolanaLogin:     {Limit: 20, Window: 10 * time.Minute},
		ginutil.RLSolanaLink:      {Limit: 12, Window: time.Hour},
	}
}
