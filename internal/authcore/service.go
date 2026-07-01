package authcore

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	stdlog "log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
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

// Additional public helpers used by OIDC flow
func (s *Service) GetProviderLink(ctx context.Context, providerSlug, subject string) (string, *string, error) {
	return s.getProviderLinkBySlug(ctx, providerSlug, subject)
}

func (s *Service) LinkProvider(ctx context.Context, userID, provider, subject string, email *string) error {
	return s.linkProvider(ctx, userID, provider, subject, email)
}

func (s *Service) SetProviderUsername(ctx context.Context, userID, provider, subject, username string) error {
	return s.setProviderUsername(ctx, userID, provider, subject, username)
}

func (s *Service) GetProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	return s.getProviderUsername(ctx, userID, provider)
}

// Convenience: Discord username
func (s *Service) GetDiscordUsername(ctx context.Context, userID string) (string, error) {
	return s.getProviderUsername(ctx, userID, "discord")
}

func (s *Service) DeriveUsername(email string) string { return deriveUsername(email) }

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

// Provider link management
func (s *Service) countProviderLinks(ctx context.Context, userID string) int {
	if s.pg == nil {
		return 0
	}
	n, _ := s.q.UserProvidersCount(ctx, userID)
	return int(n)
}
func (s *Service) hasPassword(ctx context.Context, userID string) bool {
	if s.pg == nil {
		return false
	}
	exists, _ := s.q.UserHasPassword(ctx, userID)
	return exists
}
func (s *Service) unlinkProvider(ctx context.Context, userID, provider string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider})
}

// Public wrappers
func (s *Service) CountProviderLinks(ctx context.Context, userID string) int {
	return s.countProviderLinks(ctx, userID)
}

func (s *Service) HasPassword(ctx context.Context, userID string) bool {
	return s.hasPassword(ctx, userID)
}

func (s *Service) UnlinkProvider(ctx context.Context, userID, provider string) error {
	return s.unlinkProvider(ctx, userID, provider)
}

// UserProfileLinks returns the user's linked provider slugs (non-null) and username
// aliases — the two extra lists GET /me needs beyond AdminGetUser. Keeps raw
// db.Queries out of the HTTP layer, which previously built its own db handle inline.
func (s *Service) UserProfileLinks(ctx context.Context, userID string) (providerSlugs []string, aliases []string, err error) {
	if s.pg == nil {
		return nil, nil, nil
	}
	providerSlugs, err = s.q.UserProviderSlugs(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	aliases, err = s.q.UserSlugAliases(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	return providerSlugs, aliases, nil
}

// UnlinkProviderUnlessLast atomically removes the provider link only if the user
// retains a login method afterward (a password, or another provider). Returns
// (false, nil) when removal would strip the last login method. The check and the
// delete run in one transaction, and UserProviderCountForUpdate locks the user's
// provider rows so two concurrent unlinks of different providers cannot both pass
// the "not last" check and leave the user with zero login methods.
func (s *Service) UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error) {
	if s.pg == nil {
		return false, nil
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.qtx(tx)
	links, err := q.UserProviderCountForUpdate(ctx, userID)
	if err != nil {
		return false, err
	}
	hasPwd, err := q.UserHasPassword(ctx, userID)
	if err != nil {
		return false, err
	}
	// Mirror the prior guard semantics (no password AND ≤1 provider ⇒ this is the
	// last login method), now evaluated under the row lock.
	if !hasPwd && links <= 1 {
		return false, nil
	}
	if err := q.UserProviderDeleteBySlug(ctx, db.UserProviderDeleteBySlugParams{UserID: userID, ProviderSlug: &provider}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// Issuer-based provider link helpers (preferred)
func (s *Service) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLinkByIssuerInternal(ctx, issuer, subject)
}

func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	// Store provider slug for UI, enforce uniqueness on (issuer, subject) and (user_id, issuer).
	// The delete-other-subjects (allows switching e.g. Discord accounts) and the upsert run in
	// ONE transaction: a failure can't leave the user's old link deleted and the new one missing.
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	// First delete any old link for this user+issuer with a different subject.
	if err := qtx.UserProviderDeleteOtherSubjects(ctx, db.UserProviderDeleteOtherSubjectsParams{UserID: userID, Issuer: issuer, Subject: subject}); err != nil {
		return err
	}
	// The upsert's ON CONFLICT (issuer, subject) DO UPDATE is constrained to the same user_id,
	// so a subject already owned by a DIFFERENT user yields zero affected rows (no cross-user
	// write) and RETURNING produces pgx.ErrNoRows — surfaced as a 409-class conflict.
	if _, err := qtx.UserProviderUpsertByIssuer(ctx, db.UserProviderUpsertByIssuerParams{
		ID:              providerID,
		UserID:          userID,
		Issuer:          issuer,
		ProviderSlug:    &providerSlug,
		Subject:         subject,
		EmailAtProvider: email,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authkit.ErrProviderAlreadyLinked
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	if providerSlug == SolanaProviderSlug && issuer == s.solanaIssuer() {
		s.maybeResolveSolanaSNSAfterLink(ctx, userID, subject)
	}
	return nil
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

func (s *Service) getProviderLinkByIssuerInternal(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkByIssuer(ctx, db.ProviderLinkByIssuerParams{Issuer: issuer, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

func (s *Service) getProviderLinkBySlug(ctx context.Context, providerSlug, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row, err := s.q.ProviderLinkBySlug(ctx, db.ProviderLinkBySlugParams{ProviderSlug: &providerSlug, Subject: subject})
	if err != nil {
		return "", nil, err
	}
	return row.UserID, row.EmailAtProvider, nil
}

func (s *Service) linkProvider(ctx context.Context, userID, issuer, subject string, email *string) error {
	if s.pg == nil {
		return nil
	}
	providerID, err := newUUIDV7String()
	if err != nil {
		return err
	}
	return s.q.UserProviderInsertSimple(ctx, db.UserProviderInsertSimpleParams{ID: providerID, UserID: userID, Issuer: issuer, Subject: subject, EmailAtProvider: email})
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Service) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	return s.q.UserProviderSetUsername(ctx, db.UserProviderSetUsernameParams{UserID: userID, Issuer: issuer, Subject: subject, Username: username})
}

// getProviderUsername fetches provider profile->>'username' for the given user (first match by provider).
func (s *Service) getProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	uname, err := s.q.UserProviderUsername(ctx, db.UserProviderUsernameParams{UserID: userID, ProviderSlug: &provider})
	if err != nil {
		return "", err
	}
	if uname == nil {
		return "", nil
	}
	return *uname, nil
}

// deriveUsername makes a safe username from email's local part.
func deriveUsername(email string) string {
	base := email
	if i := strings.Index(email, "@"); i > 0 {
		base = email[:i]
	}
	base = strings.ToLower(base)
	// keep alnum and underscore
	clean := make([]rune, 0, len(base))
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			clean = append(clean, r)
		}
	}
	if len(clean) == 0 {
		clean = []rune{'u', 's', 'e', 'r'}
	}
	if clean[0] < 'a' || clean[0] > 'z' {
		clean = append([]rune{'u'}, clean...)
	}
	if len(clean) > usernameMaxLen {
		clean = clean[:usernameMaxLen]
	}
	out := string(clean)
	if len(out) < usernameMinLen {
		out += "_user"
	}
	return out
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
type TwoFactorSettings struct {
	UserID       string
	Enabled      bool
	Method       string // "email", "sms", or "totp"
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	BackupCodes  []string // Hashed backup codes
	Factors      []TwoFactorFactor
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TwoFactorFactor struct {
	ID           string
	UserID       string
	Method       string
	PhoneNumber  *string
	TOTPSecret   []byte
	LastTOTPStep *int64
	IsDefault    bool
	Enabled      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Enable2FA enables two-factor authentication for a user and generates backup codes.
// Returns the plaintext backup codes (caller must show these to user ONCE).
func (s *Service) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, false)
}

func (s *Service) Enable2FADefault(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	return s.enable2FA(ctx, userID, method, phoneNumber, nil, nil, true)
}

func (s *Service) enable2FA(ctx context.Context, userID, method string, phoneNumber *string, totpSecret []byte, lastTOTPStep *int64, makeDefault bool) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	method = strings.ToLower(strings.TrimSpace(method))
	if method != "email" && method != "sms" && method != "totp" {
		return nil, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, fmt.Errorf("phone number required for SMS 2FA")
	}
	if method == "totp" && len(totpSecret) == 0 {
		return nil, fmt.Errorf("totp secret required for TOTP 2FA")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)

	var currentBackupCodes []string
	if settings, err := qtx.MFASettingsByUser(ctx, userID); err == nil && settings.Enabled {
		currentBackupCodes = settings.BackupCodes
	}

	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	firstFactor := len(factors) == 0
	makeDefault = makeDefault || firstFactor

	plaintextCodes := []string(nil)
	if len(currentBackupCodes) == 0 {
		plaintextCodes, currentBackupCodes = generateBackupCodes()
	}

	if makeDefault {
		if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
			return nil, err
		}
	}
	factor, err := qtx.MFAUpsertFactor(ctx, db.MFAUpsertFactorParams{
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phoneNumber,
		TotpSecret:   totpSecret,
		LastTotpStep: lastTOTPStep,
		IsDefault:    makeDefault,
	})
	if err != nil {
		return nil, err
	}

	_ = factor // per-factor data lives only on mfa_factors (#125)
	// Settings holds only the account-level gate + backup codes (#125).
	if err := qtx.MFAUpsertSettings(ctx, db.MFAUpsertSettingsParams{
		UserID:      userID,
		BackupCodes: currentBackupCodes,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return plaintextCodes, nil
}

// Disable2FA disables two-factor authentication for a user.
func (s *Service) Disable2FA(ctx context.Context, userID string) error {
	_, err := s.Disable2FAWithRemovedRoles(ctx, userID)
	return err
}

// Disable2FAWithRemovedRoles disables account MFA and removes active user role
// assignments whose catalog role requires MFA.
func (s *Service) Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
	qtx := s.qtx(tx)
	removed, err := s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	if err := qtx.MFADeleteAllFactors(ctx, userID); err != nil {
		return nil, err
	}
	if err := qtx.MFADisable(ctx, userID); err != nil {
		return nil, err
	}
	return removed, tx.Commit(ctx)
}

func (s *Service) Disable2FAFactor(ctx context.Context, userID, factorID string) error {
	_, err := s.Disable2FAFactorWithRemovedRoles(ctx, userID, factorID)
	return err
}

func (s *Service) Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]RemovedMFARoleAssignment, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return nil, fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.ForSchema(tx, s.dbSchema())
	qtx := s.qtx(tx)
	rows, err := qtx.MFADeleteFactor(ctx, db.MFADeleteFactorParams{UserID: userID, ID: factorID})
	if err != nil {
		return nil, err
	}
	if rows == 0 {
		return nil, pgx.ErrNoRows
	}
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	removed := []RemovedMFARoleAssignment(nil)
	if len(factors) == 0 {
		removed, err = s.removeMFARequiredUserRoles(ctx, q, strings.TrimSpace(userID))
		if err != nil {
			return nil, err
		}
		if err := qtx.MFADisable(ctx, userID); err != nil {
			return nil, err
		}
		return removed, tx.Commit(ctx)
	}
	// Promote a new default if the deleted factor was the default.
	hasDefault := false
	for _, f := range factors {
		if f.IsDefault {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factors[0].ID}); err != nil {
			return nil, err
		}
	}
	return removed, tx.Commit(ctx)
}

func (s *Service) SetDefault2FAFactor(ctx context.Context, userID, factorID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	if strings.TrimSpace(factorID) == "" {
		return fmt.Errorf("factor id required")
	}
	tx, err := s.pg.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := s.qtx(tx)
	factors, err := qtx.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return err
	}
	var selected *db.ProfilesMfaFactor
	for i := range factors {
		if factors[i].ID == factorID {
			selected = &factors[i]
			break
		}
	}
	if selected == nil {
		return pgx.ErrNoRows
	}
	if err := qtx.MFAClearDefaultFactors(ctx, userID); err != nil {
		return err
	}
	if _, err := qtx.MFASetDefaultFactor(ctx, db.MFASetDefaultFactorParams{UserID: userID, ID: factorID}); err != nil {
		return err
	}
	_ = selected // existence check only; per-factor data is not mirrored to settings (#125)
	return tx.Commit(ctx)
}

// Get2FASettings retrieves a user's 2FA settings
func (s *Service) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	row, err := s.q.MFASettingsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Settings holds only the account gate + backup codes (#125); the displayed
	// method/phone/secret are derived from the default factor below.
	settings := &TwoFactorSettings{
		UserID:      row.UserID,
		Enabled:     row.Enabled,
		BackupCodes: row.BackupCodes,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err == nil {
		settings.Factors = factors
		for _, factor := range factors {
			if factor.IsDefault {
				settings.Method = factor.Method
				settings.PhoneNumber = factor.PhoneNumber
				settings.TOTPSecret = factor.TOTPSecret
				settings.LastTOTPStep = factor.LastTOTPStep
				break
			}
		}
	}
	return settings, nil
}

func (s *Service) List2FAFactors(ctx context.Context, userID string) ([]TwoFactorFactor, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}
	rows, err := s.q.MFAListFactorsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]TwoFactorFactor, 0, len(rows))
	for _, row := range rows {
		out = append(out, twoFactorFactorFromFields(row.ID, row.UserID, row.Method, row.PhoneNumber, row.TotpSecret, row.LastTotpStep, row.IsDefault, row.CreatedAt, row.UpdatedAt))
	}
	return out, nil
}

// Require2FAForLogin sends a 2FA code to the user's configured method.
// Returns the destination (email/phone) where the code was sent.
// This should be called after successful password verification.
func (s *Service) Require2FAForLogin(ctx context.Context, userID string) (string, error) {
	destination, _, _, err := s.Require2FAForLoginFactor(ctx, userID, "")
	return destination, err
}

func (s *Service) Require2FAForLoginFactor(ctx context.Context, userID, factorID string) (destination, method string, factor TwoFactorFactor, err error) {
	factor, err = s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, "", factor)
	return destination, factor.Method, factor, err
}

func (s *Service) send2FACodeForFactor(ctx context.Context, userID, sessionID string, factor TwoFactorFactor) (string, error) {
	if !factor.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}
	if factor.Method == "totp" {
		return "authenticator app", nil
	}
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	var destination string
	if factor.Method == "email" {
		if user.Email == nil {
			return "", fmt.Errorf("no email address configured")
		}
		destination = *user.Email
	} else { // sms
		if factor.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *factor.PhoneNumber
	}

	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	if strings.TrimSpace(sessionID) == "" {
		if err := s.storeMFACode(ctx, userID, hash, factor.Method, destination, 10*time.Minute); err != nil {
			return "", err
		}
	} else if err := s.storeMFAStepUpCode(ctx, userID, sessionID, hash, factor.Method, destination, 10*time.Minute); err != nil {
		return "", err
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if factor.Method == "email" {
		if s.email != nil {
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error {
				return s.email.SendLoginCode(sendCtx, destination, username, code)
			}); err != nil {
				return "", emailDeliveryError(err)
			}
		} else {
			// In production, require email to be configured for email 2FA
			if !s.isDevEnvironment() {
				return "", fmt.Errorf("email 2FA unavailable: email sender not configured (email 2FA requires email in production)")
			}
		}
	} else { // sms
		if s.sms != nil {
			sendCtx := s.contextWithUserPreferredLanguage(ctx, userID)
			if err := s.withSendTimeout(sendCtx, func(sendCtx context.Context) error { return s.sms.SendLoginCode(sendCtx, destination, code) }); err != nil {
				return "", smsDeliveryError(err)
			}
		} else {
			// In production, require SMS to be configured for SMS 2FA
			if !s.isDevEnvironment() {
				return "", fmt.Errorf("SMS 2FA unavailable: SMS sender not configured (SMS 2FA requires delivery in production)")
			}
		}
	}
	return destination, nil
}

// Require2FAForStepUp sends a 2FA code for authenticated step-up.
func (s *Service) Require2FAForStepUp(ctx context.Context, userID, sessionID string) (destination, method string, err error) {
	destination, method, _, err = s.Require2FAForStepUpMethod(ctx, userID, sessionID, "")
	return destination, method, err
}

func (s *Service) Require2FAForStepUpFactor(ctx context.Context, userID, sessionID, factorID string) (destination, method string, factor TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

func (s *Service) Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor TwoFactorFactor, err error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", "", TwoFactorFactor{}, jwt.ErrTokenInvalidClaims
	}
	factor, err = s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return "", "", TwoFactorFactor{}, err
	}
	destination, err = s.send2FACodeForFactor(ctx, userID, sessionID, factor)
	return destination, factor.Method, factor, err
}

// Verify2FAStepUpCode verifies a session-scoped 2FA step-up code.
func (s *Service) Verify2FAStepUpCode(ctx context.Context, userID, sessionID, code string) (bool, error) {
	return s.Verify2FAStepUpMethodCode(ctx, userID, sessionID, "", code)
}

func (s *Service) Verify2FAStepUpFactorCode(ctx context.Context, userID, sessionID, factorID, code string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, jwt.ErrTokenInvalidClaims
	}
	factor, err := s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

func (s *Service) Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return false, jwt.ErrTokenInvalidClaims
	}
	factor, err := s.twoFactorFactorByMethod(ctx, userID, method)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	return s.consumeMFAStepUpCode(ctx, userID, sessionID, sha256Hex(code), factor.Method)
}

// Create2FAChallenge creates a short-lived challenge to prove password verification before 2FA.
func (s *Service) Create2FAChallenge(ctx context.Context, userID string) (string, error) {
	if !s.useEphemeralStore() {
		return "", fmt.Errorf("ephemeral store not configured")
	}
	challenge := randB64(32)
	hash := sha256Hex(challenge)
	if err := s.storeMFAChallenge(ctx, userID, hash, 10*time.Minute); err != nil {
		return "", err
	}
	return challenge, nil
}

// Verify2FAChallenge verifies the challenge created during the password step.
func (s *Service) Verify2FAChallenge(ctx context.Context, userID, challenge string) (bool, error) {
	if strings.TrimSpace(challenge) == "" {
		return false, nil
	}
	if !s.useEphemeralStore() {
		return false, fmt.Errorf("ephemeral store not configured")
	}
	stored, ok, err := s.getMFAChallenge(ctx, userID)
	if err != nil || !ok {
		return false, err
	}
	return stored == sha256Hex(challenge), nil
}

// Clear2FAChallenge removes the stored challenge after successful 2FA verification.
func (s *Service) Clear2FAChallenge(ctx context.Context, userID string) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	return s.deleteMFAChallenge(ctx, userID)
}

// Verify2FACode verifies a 2FA code entered by the user during login.
// Returns true if code is valid, false otherwise.
func (s *Service) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	return s.Verify2FAFactorCode(ctx, userID, "", code)
}

func (s *Service) Verify2FAFactorCode(ctx context.Context, userID, factorID, code string) (bool, error) {
	factor, err := s.twoFactorFactor(ctx, userID, factorID)
	if err != nil {
		return false, err
	}
	if factor.Method == "totp" {
		return s.verifyTOTPFactorCode(ctx, factor, code)
	}

	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		return s.consumeMFACode(ctx, userID, hash)
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

func (s *Service) verifyTOTPFactorCode(ctx context.Context, factor TwoFactorFactor, code string) (bool, error) {
	secret, err := s.decryptTOTPSecret(factor.TOTPSecret)
	if err != nil {
		return false, err
	}
	step, ok, err := matchingTOTPStep(secret, code, time.Now())
	if err != nil || !ok {
		return false, err
	}
	if strings.TrimSpace(factor.ID) == "" {
		return false, fmt.Errorf("totp factor has no id")
	}
	rows, err := s.q.MFAConsumeFactorTOTPStep(ctx, db.MFAConsumeFactorTOTPStepParams{ID: factor.ID, UserID: factor.UserID, Step: &step})
	return rows > 0, err
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}

	// Atomic single-use consume in one statement: the DB removes the hashed code
	// and reports whether THIS call was the one that removed it. This replaces the
	// former read-filter-rewrite, which let two concurrent submissions of the same
	// code both succeed. The query's `enabled = true` predicate also subsumes the
	// old "2FA not enabled" check (callers treat (false, nil) and that error
	// identically — both reject the code).
	hash := sha256Hex(backupCode)
	rows, err := s.q.MFAConsumeBackupCode(ctx, db.MFAConsumeBackupCodeParams{CodeHash: hash, UserID: userID})
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

// RegenerateBackupCodes generates new backup codes for a user (invalidating old ones).
// Returns the plaintext codes (caller must show these to user ONCE).
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	// Verify 2FA is enabled
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil || !settings.Enabled {
		return nil, fmt.Errorf("2FA not enabled")
	}

	// Generate 10 new backup codes
	plaintextCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8)
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}

	if err := s.q.MFASetBackupCodes(ctx, db.MFASetBackupCodesParams{BackupCodes: hashedCodes, UserID: userID}); err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

func (s *Service) twoFactorFactor(ctx context.Context, userID, factorID string) (TwoFactorFactor, error) {
	if s.pg == nil {
		return TwoFactorFactor{}, fmt.Errorf("postgres not configured")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	if strings.TrimSpace(factorID) != "" {
		for _, factor := range factors {
			if factor.ID == factorID {
				return factor, nil
			}
		}
		return TwoFactorFactor{}, pgx.ErrNoRows
	}
	for _, factor := range factors {
		if factor.IsDefault {
			return factor, nil
		}
	}
	return factors[0], nil
}

func (s *Service) twoFactorFactorByMethod(ctx context.Context, userID, method string) (TwoFactorFactor, error) {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return s.twoFactorFactor(ctx, userID, "")
	}
	if method != "email" && method != "sms" && method != "totp" {
		return TwoFactorFactor{}, fmt.Errorf("invalid 2FA method: must be 'email', 'sms', or 'totp'")
	}
	factors, err := s.List2FAFactors(ctx, userID)
	if err != nil {
		return TwoFactorFactor{}, err
	}
	if len(factors) == 0 {
		settings, err := s.Get2FASettings(ctx, userID)
		if err != nil || !settings.Enabled || len(settings.Factors) == 0 {
			return TwoFactorFactor{}, fmt.Errorf("2FA not enabled")
		}
		factors = settings.Factors
	}
	for _, factor := range factors {
		if factor.Enabled && strings.EqualFold(factor.Method, method) {
			return factor, nil
		}
	}
	return TwoFactorFactor{}, pgx.ErrNoRows
}

func twoFactorFactorFromFields(id, userID, method string, phone *string, secret []byte, step *int64, isDefault bool, createdAt, updatedAt time.Time) TwoFactorFactor {
	return TwoFactorFactor{
		ID:           id,
		UserID:       userID,
		Method:       method,
		PhoneNumber:  phone,
		TOTPSecret:   secret,
		LastTOTPStep: step,
		IsDefault:    isDefault,
		Enabled:      true, // #125: a factor row existing IS the enabled state
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}
}

func generateBackupCodes() (plaintextCodes, hashedCodes []string) {
	plaintextCodes = make([]string, 10)
	hashedCodes = make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8)
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}
	return plaintextCodes, hashedCodes
}

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
