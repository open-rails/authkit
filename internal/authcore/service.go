package authcore

import (
	"context"
	"crypto"
	"fmt"
	stdlog "log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/db"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/open-rails/authkit/password"
)

// Options configures issued tokens and identifiers.
type Options struct {
	Issuer               string
	IssuedAudiences      []string // JWT audiences - tokens issued will contain ALL of these audiences
	ExpectedAudiences    []string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SessionMaxPerUser    int
	// Optional link building.
	BaseURL string
	// OIDCReturnPath is the host-owned frontend route that receives full-page OIDC login results.
	OIDCReturnPath            string
	FrontendVerifyPath        string
	FrontendPasswordResetPath string
	FrontendPasswordlessPath  string
	FrontendInvitePath        string
	PasskeyRPID               string
	PasskeyRPDisplayName      string
	PasskeyOrigins            []string
	PasskeyUserVerification   string
	// Schema is the Postgres schema AuthKit's tables live in. Empty defaults to
	// "profiles". Must match ^[a-z_][a-z0-9_]*$ (max 63 bytes); NewService
	// panics on an invalid non-empty value because a malformed name would be
	// spliced into SQL text (see internal/db.ForSchema). Prefer NewFromConfig,
	// which returns the validation error instead.
	Schema string
	// RegistrationVerification controls whether registration verification is disabled,
	// non-blocking, or required.
	RegistrationVerification RegistrationVerificationPolicy

	// VerificationSendTimeout bounds each in-line email/SMS provider send
	// (verification codes, password-reset links, login codes) so a configured
	// but misconfigured/unreachable provider cannot hang the request that
	// triggered it (e.g. registration). Empty/<=0 defaults to 15 seconds.
	VerificationSendTimeout time.Duration

	// NativeUserRegistrationMode controls public native-user self-registration.
	NativeUserRegistrationMode RegistrationMode
	// PasswordlessLoginEnabled enables contact-based passwordless sessions.
	PasswordlessLoginEnabled bool
	// PasswordlessAutoRegistrationEnabled allows unknown verified contacts to
	// create no-password users during passwordless confirmation.
	PasswordlessAutoRegistrationEnabled bool

	// Environment is host-provided runtime mode used for dev/prod behavior checks.
	Environment string
	// SolanaNetwork is host-provided chain selector for SIWS flows. SNS resolution is
	// AuthKit-owned and always-on with a fixed timeout/cache — there is no host override.
	SolanaNetwork string

	// APIKeyPrefix is the issuing application's brand prefix for generated API
	// keys (validated lowercase-alnum, 1-16 chars; empty -> bare st_).
	APIKeyPrefix string
	// APIKeyMaxTTL caps a minted API key's expiry (0 = no cap).
	APIKeyMaxTTL time.Duration
	// TOTPSecretKey encrypts persisted authenticator-app shared secrets.
	TOTPSecretKey []byte
	// TwoFactorMode is the account-wide 2FA policy (Disabled/Optional/Required).
	// Empty is treated as Optional. Mapped from TwoFactorConfig.Mode.
	TwoFactorMode TwoFactorMode
	// TwoFactorMethods is the set of enabled second-factor channels. Empty means
	// all (email/sms/totp). Mapped from TwoFactorConfig.Methods.
	TwoFactorMethods []TwoFactorMethod
	// RequireMFAEnrollment forces every user to enroll a second factor: without
	// usable 2FA, a user cannot establish or refresh a session (returns
	// ErrTwoFAEnrollmentRequired). Derived from TwoFactorMode == Required.
	RequireMFAEnrollment bool
}

// Keyset holds the active signer and the public keys exposed via JWKS.
type Keyset struct {
	Active     jwtkit.Signer
	PublicKeys map[string]crypto.PublicKey // kid -> pub
}

// EntitlementsProvider returns the names of a user's currently active
// application entitlements (e.g., billing tiers). Names are the ONLY shape
// AuthKit consumes — they are baked verbatim into the `entitlements` claim of
// access tokens and surfaced on admin user views. Providers should return
// active grants only; expired/revoked entitlements are the provider's concern,
// not AuthKit's.
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userID string) ([]string, error)
}

// BatchEntitlementsProvider is an optional upgrade of EntitlementsProvider:
// one call answers many users, so list renders (AdminListUsers) cost one
// provider round trip instead of one per row. Detected by type assertion;
// providers without it get the per-user fallback. Unknown user ids may be
// absent from the result.
type BatchEntitlementsProvider interface {
	ListEntitlementsBatch(ctx context.Context, userIDs []string) (map[string][]string, error)
}

// EntitlementFilterProvider is the REVERSE of EntitlementsProvider: given an
// entitlement key, it returns the subject ids that currently hold it. AuthKit
// owns the user DIRECTORY; the billing system (OpenRails) owns "who is entitled",
// so filtering the directory BY entitlement delegates here instead of joining
// across schemas. Subject ids ARE user ids (UUID-only payable identity). Detected
// by type assertion on the entitlements provider; when absent, AdminListUsers
// with an Entitlement filter fails with ErrEntitlementFilterUnavailable so the
// misconfiguration is loud rather than silently returning everyone.
type EntitlementFilterProvider interface {
	ListSubjectsWithEntitlement(ctx context.Context, entitlement string) ([]string, error)
}

// HashAlgoLegacyResetRequired marks profiles.user_passwords rows migrated from
// legacy systems whose stored hashes can never verify (DES crypt, md5-crypt,
// corrupted values). The raw legacy hash is preserved in password_hash for
// forensics only; the sole way forward for these accounts is a password reset.
const HashAlgoLegacyResetRequired = "legacy-reset-required"

var (
	// ErrUserBanned indicates the account is blocked from authenticating.
	ErrUserBanned = authkit.ErrUserBanned
	// ErrPasswordResetRequired indicates the account's stored password hash is
	// flagged HashAlgoLegacyResetRequired: no plaintext can ever verify against
	// it, so the user must complete a password reset before password auth (login,
	// step-up, change-password) can succeed. HTTP layers map this to the stable
	// code "password_reset_required".
	ErrPasswordResetRequired = authkit.ErrPasswordResetRequired
	// ErrUserNotFound indicates a user does not exist (or is not visible).
	ErrUserNotFound = authkit.ErrUserNotFound
	// ErrInvalidUntil indicates a time-limited operation has a non-future expiry.
	ErrInvalidUntil = authkit.ErrInvalidUntil
	// ErrEmailAlreadyVerified indicates an email verification request targeted an already-verified email.
	ErrEmailAlreadyVerified = authkit.ErrEmailAlreadyVerified
	// ErrPhoneAlreadyVerified indicates a phone verification request targeted an already-verified phone.
	ErrPhoneAlreadyVerified = authkit.ErrPhoneAlreadyVerified
	// ErrPendingRegistrationNotFound indicates a registration resend request did not match a pending registration.
	ErrPendingRegistrationNotFound = authkit.ErrPendingRegistrationNotFound
	// ErrRegistrationDisabled indicates a public user-creation path was attempted
	// while native-user registration is bootstrap-only. Existing-user
	// authentication is unaffected; only NEW account creation through
	// public/auto-registration is blocked.
	ErrRegistrationDisabled = authkit.ErrRegistrationDisabled
	// ErrVerificationLinkExpired indicates a verification link/token no longer has a pending verification record.
	ErrVerificationLinkExpired = authkit.ErrVerificationLinkExpired
	ErrEmailInUse              = authkit.ErrEmailInUse
	ErrPhoneInUse              = authkit.ErrPhoneInUse
	ErrEmailSenderUnavailable  = authkit.ErrEmailSenderUnavailable
	ErrSMSSenderUnavailable    = authkit.ErrSMSSenderUnavailable
	ErrPasswordlessDisabled    = authkit.ErrPasswordlessDisabled
)

// (storage layer collapsed into direct Postgres/Redis helpers)

// Service is the core auth service used by HTTP adapters.
type Service struct {
	opts              Options
	keys              Keyset
	email             EmailSender
	sms               SMSSender
	pg                *pgxpool.Pool
	q                 *db.Queries
	schema            string       // validated Postgres schema name; db.DefaultSchema when unset
	groupSchema       *GroupSchema // #111 permission-group persona schema (nil ⇒ root-only default)
	entitlements      EntitlementsProvider
	authlog           *clickHouseAuthLog // session-event sink/reader; nil unless WithClickHouse
	solanaSNSResolver defaultSolanaSNSResolver
	// snsCacheTTLOverride is a test-only seam for forcing SNS cache staleness; 0 in
	// production, where solanaSNSCacheTTL() falls back to the fixed 24h constant.
	snsCacheTTLOverride time.Duration
	ephemeralStore      EphemeralStore
	ephemeralMode       EphemeralMode
	// cfg is the host Config this Service was built from, retained so the HTTP
	// transport (client-first NewServer) can read HTTP-layer config that rides in
	// Config but the engine doesn't consume (OIDC providers/descriptors). Zero
	// value for NewService-constructed (config-less) services.
	cfg            Config
	verifyWarnOnce sync.Once

	// SMS deliverability health, populated by CheckSMSHealth. Until a check has
	// run, SMS is considered available whenever a sender is configured (legacy
	// behavior). Once a check runs, phone flows gate on the result.
	smsHealthChecked atomic.Bool
	smsHealthy       atomic.Bool
	smsHealthReason  atomic.Value // string
}

// SessionEventHistoryEnabled reports whether ClickHouse session-event history is
// wired (WithClickHouse). The admin sign-in routes report unavailable when false.
func (s *Service) SessionEventHistoryEnabled() bool { return s.authlog != nil }

// ListSessionEvents returns a user's recent session events from ClickHouse, most
// recent first. Empty when ClickHouse is not configured.
func (s *Service) ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error) {
	if s.authlog == nil {
		return nil, nil
	}
	return s.authlog.ListSessionEvents(ctx, userID, eventTypes...)
}

// LogSessionCreated records a session creation event to ClickHouse (best-effort).
func (s *Service) LogSessionCreated(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	m := strings.TrimSpace(method)
	var mPtr *string
	if m != "" {
		mPtr = &m
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventCreated,
		Method:     mPtr,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

func (s *Service) logSessionRevoked(ctx context.Context, userID string, sessionID string, reason *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventRevoked,
		Method:     nil,
		Reason:     reason,
		IPAddr:     nil,
		UserAgent:  nil,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogPasswordChanged records a password change event for a user (best-effort).
func (s *Service) LogPasswordChanged(ctx context.Context, userID string, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordChange,
		Method:     nil,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogPasswordRecovery records a password recovery event for a user (best-effort).

func (s *Service) LogPasswordRecovery(ctx context.Context, userID string, method, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordRecovery,
		Method:     &method,
		Reason:     nil,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// LogSessionFailed records a failed session event for a user (best-effort).

func (s *Service) LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	e := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.opts.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventFailed,
		Method:     nil,
		Reason:     reason,
		IPAddr:     ip,
		UserAgent:  ua,
	}
	_ = s.authlog.LogSessionEvent(ctx, e)
}

// SendWelcome triggers the welcome email if an EmailSender is configured.
func (s *Service) SendWelcome(ctx context.Context, userID string) {
	if s.email == nil || s.pg == nil || strings.TrimSpace(userID) == "" {
		return
	}
	// Look up user's email and username
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
	_ = s.email.SendWelcome(sendCtx, *u.Email, username)
}

func (s *Service) hasPassword(ctx context.Context, userID string) bool {
	if s.pg == nil {
		return false
	}
	exists, _ := s.q.UserHasPassword(ctx, userID)
	return exists
}

// HasPassword reports whether the user has a local password set.
func (s *Service) HasPassword(ctx context.Context, userID string) bool {
	return s.hasPassword(ctx, userID)
}

// ListEntitlements returns current entitlement names for a user (fresh from
// the provider). A provider failure is logged and returned as none — callers
// (admin user views) degrade rather than fail.
func (s *Service) ListEntitlements(ctx context.Context, userID string) []string {
	if s.entitlements == nil {
		return nil
	}
	ents, err := s.entitlements.ListEntitlements(ctx, userID)
	if err != nil {
		stdlog.Printf("authkit: error: entitlements provider failed for user %s; reporting no entitlements: %v", userID, err)
		return nil
	}
	return ents
}

// (legacy ChangePassword removed in favor of unified ChangePassword with session revocation)

// --- Pending Registration Helpers ---

// PendingRegistration represents an unverified registration
type PendingRegistration struct {
	Email             string
	Username          string
	PasswordHash      string
	PreferredLanguage string
}

// GetPendingRegistrationByEmail looks up a pending registration by email.
func (s *Service) GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, KindRegisterEmail, email)
	if !ok {
		return nil, nil
	}
	return &PendingRegistration{
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
	}, nil
}

// GetPendingPhoneRegistrationByPhone looks up a pending phone registration by phone number.
// (PendingRegistration.Email carries the phone for phone registrations, preserving prior behavior.)
func (s *Service) GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, KindRegisterPhone, phone)
	if !ok {
		return nil, nil
	}
	return &PendingRegistration{
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
	}, nil
}

// VerifyPendingPassword checks if the provided password matches the pending registration's hash.
// Returns true if password is correct, false otherwise.
func (s *Service) VerifyPendingPassword(ctx context.Context, email, pass string) bool {
	pr, err := s.GetPendingRegistrationByEmail(ctx, email)
	if err != nil || pr == nil {
		return false
	}

	// Pending registrations always use argon2id (from CreatePendingRegistration)
	ok, err := password.VerifyArgon2id(pr.PasswordHash, pass)
	return err == nil && ok
}

// VerifyPendingPhonePassword checks if the provided password matches the pending
// phone registration's hash. Returns true if password is correct, false otherwise.
func (s *Service) VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool {
	pr, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone)
	if err != nil || pr == nil {
		return false
	}
	ok, err := password.VerifyArgon2id(pr.PasswordHash, pass)
	return err == nil && ok
}

// --- Two-Factor Authentication (2FA) ---

// TwoFactorSettings represents a user's 2FA configuration

// (SetUserActive removed; use BanUser/UnbanUser or SoftDeleteUser.)

// requirePG returns an error when no Postgres pool is configured (verify-only /
// config-only construction). Store-backed methods guard on it.
func (s *Service) requirePG() error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	return nil
}

// dedupeStrings trims, drops empties, and de-duplicates a string slice,
// preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
