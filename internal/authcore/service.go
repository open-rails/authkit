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
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/password"
)

// Keyset is a fixed active signer + public-key set for the low-level
// NewService constructor (explicit-key tests). It is converted to a
// jwtkit.KeySource at construction and never read again directly — hosts that
// need rotation should provide a live jwtkit.KeySource via
// Config.Keys.Source / NewFromConfig instead. See #238.
type Keyset struct {
	Active     jwtkit.Signer
	PublicKeys map[string]crypto.PublicKey // kid -> pub
}

// EntitlementsProvider returns the names of users' currently active
// application entitlements (e.g., billing tiers). Names are the ONLY shape
// AuthKit consumes — they are baked verbatim into the `entitlements` claim of
// access tokens and surfaced on admin user views. Providers should return
// active grants only; expired/revoked entitlements are the provider's concern,
// not AuthKit's.
//
// BATCH-NATIVE (#221, operation-shape rule #219): one call answers many users —
// the map is keyed by user id and unknown/entitlement-less ids are simply
// absent. A single-user read is the batch with a one-element slice. (This
// replaces the former single-user signature plus the optional
// BatchEntitlementsProvider type-assertion upgrade.)
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userIDs []string) (map[string][]string, error)
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
	// keys is read per-operation (ActiveSigner/PublicKeys), never snapshotted:
	// a live jwtkit.KeySource (e.g. the reloadable file source) hot-swaps keys
	// behind an atomic pointer, and the Service must observe every swap (#238).
	keys              jwtkit.KeySource
	email             EmailSender
	sms               SMSSender
	pg                *pgxpool.Pool
	q                 *db.Queries
	schema            string       // validated Postgres schema name; db.DefaultSchema when unset
	groupSchema       *GroupSchema // #111 permission-group persona schema (nil ⇒ root-only default)
	entitlements      EntitlementsProvider
	solanaSNSResolver defaultSolanaSNSResolver
	// snsCacheTTLOverride is a test-only seam for forcing SNS cache staleness; 0 in
	// production, where solanaSNSCacheTTL() falls back to the fixed 24h constant.
	snsCacheTTLOverride time.Duration
	ephemeralStore      EphemeralStore
	// cfg is THE configuration (#237): the host Config, normalized exactly once
	// at construction (normalizeConfig). The engine and the HTTP transport both
	// read it — there is no parallel flat options struct.
	cfg            Config
	verifyWarnOnce sync.Once

	// SMS deliverability health, populated by CheckSMSHealth. Until a check has
	// run, SMS is considered available whenever a sender is configured (legacy
	// behavior). Once a check runs, phone flows gate on the result.
	smsHealthChecked atomic.Bool
	smsHealthy       atomic.Bool
	smsHealthReason  atomic.Value // string
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
// the provider — a one-element batch, #221). A provider failure is logged and
// returned as none — callers (admin user views) degrade rather than fail.
func (s *Service) ListEntitlements(ctx context.Context, userID string) []string {
	if s.entitlements == nil {
		return nil
	}
	m, err := s.entitlements.ListEntitlements(ctx, []string{userID})
	if err != nil {
		stdlog.Printf("authkit: error: entitlements provider failed for user %s; reporting no entitlements: %v", userID, err)
		return nil
	}
	return m[userID]
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
