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
}

// NewService constructs a core.Service and wraps it for HTTP mounting.
// Returns an error if the core service fails to initialize (e.g., missing keys in production).
func NewService(cfg core.Config) (*Service, error) {
	coreSvc, err := core.NewFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	prov := cfg.Providers
	s := &Service{svc: coreSvc, oidcProviders: prov}
	return s, nil
}

func (s *Service) WithPostgres(pg *pgxpool.Pool) *Service { s.svc = s.svc.WithPostgres(pg); return s }
func (s *Service) WithEntitlements(p core.EntitlementsProvider) *Service {
	s.svc = s.svc.WithEntitlements(p)
	return s
}
func (s *Service) WithRedis(rd *redis.Client) *Service             { s.rd = rd; return s }
func (s *Service) WithRateLimiter(rl ginutil.RateLimiter) *Service { s.rl = rl; return s }
func (s *Service) WithEmailSender(es core.EmailSender) *Service {
	s.svc = s.svc.WithEmailSender(es)
	return s
}

func (s *Service) WithSMSSender(sender core.SMSSender) *Service {
	s.svc = s.svc.WithSMSSender(sender)
	return s
}

// WithAuthLogger wires a custom authentication event logger (e.g., ClickHouse sink).
func (s *Service) WithAuthLogger(l core.AuthEventLogger) *Service {
	s.svc = s.svc.WithAuthLogger(l)
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
func (s *Service) GinRegisterOIDC(root gin.IRouter) *Service {
	rl := s.ensureLimiter()
	_ = rl // currently used inside handlers; keep initialized for rate limits
	providers := s.oidcProviders
	if providers == nil {
		providers = map[string]oidckit.RPConfig{}
	}
	mgr := oidckit.NewManagerFromMinimal(providers)
	state := s.stateCache()
	oidcCfg := handlers.OIDCConfig{Manager: mgr, StateCache: state}
	root.GET("/auth/oidc/:provider/login", handlers.HandleOIDCLoginGET(oidcCfg, s.svc, rl))
	root.GET("/auth/oidc/:provider/callback", handlers.HandleOIDCCallbackGET(oidcCfg, s.svc, nil, rl))
	if _, ok := providers["discord"]; ok {
		root.GET("/auth/oauth/discord/login", handlers.HandleDiscordLoginGET(oidcCfg, s.svc, rl))
		root.GET("/auth/oauth/discord/callback", handlers.HandleDiscordCallbackGET(oidcCfg, s.svc, rl))
	}
	return s
}

// GinRegisterAPI mounts JSON API endpoints under the given router/group (e.g., /api/v1).
func (s *Service) GinRegisterAPI(api gin.IRouter) *Service {
	rl := s.ensureLimiter()
	auth := MiddlewareFromSVC(s)

	api.POST("/auth/password/login", handlers.HandlePasswordLoginPOST(s.svc, rl))

	// Unified registration (accepts email or phone in identifier field)
	api.POST("/auth/register", handlers.HandleRegisterUnifiedPOST(s.svc, rl))
	api.POST("/auth/register/resend-email", handlers.HandlePendingRegistrationResendPOST(s.svc, rl))
	api.POST("/auth/register/resend-phone", handlers.HandlePhoneRegisterResendPOST(s.svc, rl))

	// Email-based password reset and verification
	api.POST("/auth/password/reset/request", handlers.HandlePasswordResetRequestPOST(s.svc, rl))
	api.POST("/auth/password/reset/confirm", handlers.HandlePasswordResetConfirmPOST(s.svc, rl))
	api.POST("/auth/email/verify/request", handlers.HandleEmailVerifyRequestPOST(s.svc, rl))
	api.POST("/auth/email/verify/confirm", handlers.HandleEmailVerifyConfirmPOST(s.svc, rl))

	// Phone-based password reset and verification
	api.POST("/auth/phone/verify/request", handlers.HandlePhoneVerifyRequestPOST(s.svc, rl))
	api.POST("/auth/phone/verify/confirm", handlers.HandlePhoneVerifyConfirmPOST(s.svc, rl))
	api.POST("/auth/phone/password/reset/request", handlers.HandlePhonePasswordResetRequestPOST(s.svc, rl))
	api.POST("/auth/phone/password/reset/confirm", handlers.HandlePhonePasswordResetConfirmPOST(s.svc, rl))

	// Provider link start (OIDC)
	providers := s.oidcProviders
	if providers == nil {
		providers = map[string]oidckit.RPConfig{}
	}
	mgr := oidckit.NewManagerFromMinimal(providers)
	state := s.stateCache()
	oidcCfg := handlers.OIDCConfig{Manager: mgr, StateCache: state}
	api.POST("/auth/oidc/:provider/link/start", auth.Required(), handlers.HandleOIDCLinkStartPOST(oidcCfg, s.svc, rl))
	// Discord link start (OAuth2)
	if _, ok := providers["discord"]; ok {
		api.POST("/auth/oauth/discord/link/start", auth.Required(), handlers.HandleDiscordLinkStartPOST(oidcCfg, s.svc, rl))
	}

	// Sessions + logout
	api.POST("/auth/token", handlers.HandleAuthTokenPOST(s.svc, rl))
	api.POST("/auth/sessions/current", handlers.HandleAuthSessionsCurrentPOST(s.svc, rl))
	api.POST("/auth/user/password", auth.Required(), handlers.HandleUserPasswordPOST(s.svc, rl))
	api.GET("/auth/user/sessions", auth.Required(), handlers.HandleUserSessionsGET(s.svc, rl))
	api.DELETE("/auth/user/sessions/:id", auth.Required(), handlers.HandleUserSessionDELETE(s.svc, rl))
	api.DELETE("/auth/user/sessions", auth.Required(), handlers.HandleUserSessionsDELETE(s.svc, rl))
	api.DELETE("/auth/logout", auth.Required(), handlers.HandleLogoutDELETE(s.svc, rl))

	// User routes
	api.GET("/auth/user/me", auth.Required(), LookupDBUser(s.svc.Postgres()), handlers.HandleUserMeGET(s.svc, rl))
	api.PATCH("/auth/user/username", auth.Required(), handlers.HandleUserUsernamePATCH(s.svc, rl))
	api.POST("/auth/user/email/change/request", auth.Required(), handlers.HandleUserEmailChangeRequestPOST(s.svc, rl))
	api.POST("/auth/user/email/change/confirm", auth.Required(), handlers.HandleUserEmailChangeConfirmPOST(s.svc, rl))
	api.POST("/auth/user/email/change/resend", auth.Required(), handlers.HandleUserEmailChangeResendPOST(s.svc, rl))
	api.PATCH("/auth/user/biography", auth.Required(), handlers.HandleUserBiographyPATCH(s.svc))
	api.DELETE("/auth/user", auth.Required(), handlers.HandleUserDeleteDELETE(s.svc, rl))
	api.DELETE("/auth/user/providers/:provider", auth.Required(), handlers.HandleUserUnlinkProviderDELETE(s.svc, rl))

	// Two-Factor Authentication routes
	api.GET("/auth/user/2fa", auth.Required(), handlers.HandleUser2FAStatusGET(s.svc, rl))
	api.POST("/auth/user/2fa/enable", auth.Required(), handlers.HandleUser2FAEnablePOST(s.svc, rl))
	api.POST("/auth/user/2fa/disable", auth.Required(), handlers.HandleUser2FADisablePOST(s.svc, rl))
	api.POST("/auth/user/2fa/regenerate-codes", auth.Required(), handlers.HandleUser2FARegenerateCodesPOST(s.svc, rl))
	api.POST("/auth/2fa/verify", handlers.HandleUser2FAVerifyPOST(s.svc, rl)) // No auth required - this is during login

	// Admin routes
	admin := api.Group("/auth/admin").Use(auth.RequireAdmin(s.svc.Postgres()))
	admin.POST("/roles/grant", handlers.HandleAdminRolesGrantPOST(s.svc, rl))
	admin.POST("/roles/revoke", handlers.HandleAdminRolesRevokePOST(s.svc, rl))
	admin.GET("/users", handlers.HandleAdminUsersListGET(s.svc, rl))
	admin.GET("/users/:user_id", handlers.HandleAdminUserGET(s.svc))
	admin.POST("/users/ban", handlers.HandleAdminUsersBanPOST(s.svc, rl))
	admin.POST("/users/unban", handlers.HandleAdminUsersUnbanPOST(s.svc, rl))
	admin.POST("/users/set-email", handlers.HandleAdminUsersSetEmailPOST(s.svc, rl))
	admin.POST("/users/set-username", handlers.HandleAdminUsersSetUsernamePOST(s.svc, rl))
	admin.DELETE("/users/:user_id", handlers.HandleAdminUserDeleteDELETE(s.svc, rl))
	admin.GET("/users/:user_id/signins", handlers.HandleAdminUserSigninsGET(s.svc, rl))

	// Solana SIWS authentication routes
	siwsCfg := handlers.SIWSConfig{
		Cache:  s.siwsCache(),
		Domain: s.solanaDomain,
	}
	api.POST("/auth/solana/challenge", handlers.HandleSolanaChallengePost(siwsCfg, s.svc, rl))
	api.POST("/auth/solana/login", handlers.HandleSolanaLoginPost(siwsCfg, s.svc, rl))
	api.POST("/auth/solana/link", auth.Required(), handlers.HandleSolanaLinkPost(siwsCfg, s.svc, rl))

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
		"default":                            {Limit: 120, Window: time.Minute},
		ginutil.RLAuthToken:                  {Limit: 30, Window: time.Minute},
		ginutil.RLAuthRegister:               {Limit: 10, Window: time.Hour},
		ginutil.RLAuthRegisterResendEmail:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthRegisterResendPhone:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthLogout:                 {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLPasswordLogin:              {Limit: 20, Window: time.Hour},
		ginutil.RLPasswordResetRequest:       {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLPasswordResetConfirm:       {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyRequest:         {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyConfirm:         {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLPhoneVerifyRequest:         {Limit: 3, Window: 10 * time.Minute}, // SMS is costly - 3/10min, ~6/hour
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
		"default":                            {Limit: 120, Window: time.Minute},
		ginutil.RLAuthToken:                  {Limit: 30, Window: time.Minute},
		ginutil.RLAuthRegister:               {Limit: 10, Window: time.Hour},
		ginutil.RLAuthRegisterResendEmail:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthRegisterResendPhone:    {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLAuthLogout:                 {Limit: 60, Window: 10 * time.Minute},
		ginutil.RLPasswordLogin:              {Limit: 20, Window: time.Hour},
		ginutil.RLPasswordResetRequest:       {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLPasswordResetConfirm:       {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyRequest:         {Limit: 6, Window: 10 * time.Minute},
		ginutil.RLEmailVerifyConfirm:         {Limit: 10, Window: 10 * time.Minute},
		ginutil.RLPhoneVerifyRequest:         {Limit: 3, Window: 10 * time.Minute}, // SMS is costly - 3/10min, ~6/hour
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
