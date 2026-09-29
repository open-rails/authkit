package engine

import (
	"context"
	"crypto"
	"fmt"
	stdlog "log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// Keyset is a fixed active signer + public-key set for the low-level
// NewService constructor (explicit-key tests). It is converted to a
// jwtkit.KeySource at construction and never read again directly — hosts that
// need rotation should provide a live jwtkit.KeySource via
// Config.Keys.Source / NewFromConfig instead. See #238.
type keyset struct {
	Active     jwtkit.Signer
	PublicKeys map[string]crypto.PublicKey // kid -> pub
}

// EntitlementsProvider mirrors authkit.EntitlementsProvider.
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userIDs []string) (map[string][]string, error)
}

// entitlementFilterProvider mirrors authkit.EntitlementFilterProvider.
type entitlementFilterProvider interface {
	ListSubjectsWithEntitlement(ctx context.Context, entitlement string) ([]string, error)
}

// (storage layer collapsed into direct Postgres helpers)

// Engine owns local business logic and resources behind Auth.
type Engine struct {
	closeOnce sync.Once

	maintenance  *riverMaintenance
	onSoftDelete func(context.Context, iam.UserDeletion) error
	onHardDelete func(context.Context, iam.UserDeletion) error
	onRestore    func(context.Context, iam.UserDeletion) error

	// keys is read per-operation (ActiveSigner/PublicKeys), never snapshotted:
	// a live jwtkit.KeySource (e.g. the reloadable file source) hot-swaps keys
	// behind an atomic pointer, and the engine must observe every swap (#238).
	keys jwtkit.KeySource

	// Only resources allocated by New are closed with the client.
	ownedKeySource *jwtkit.FileKeySource

	email        EmailSender
	sms          SMSSender
	pg           *pgxpool.Pool
	q            *db.Queries
	schema       string       // validated Postgres schema name; db.DefaultSchema when unset
	groupSchema  *rbac.Schema // compiled Config.Roles (nil ⇒ root-only default)
	entitlements atomic.Pointer[entitlementsBox]
	// delegationAuthorizer is the host-injected authorizer for the
	// delegated-token mint route (#277); required when the route is mounted.
	delegationAuthorizer iam.DelegationAuthorizer
	solanaSNSResolver    SolanaSNSResolver
	sns                  solanaSNS
	// now is the engine clock for TTL/grace decisions; Deps.Clock overrides it.
	now       func() time.Time
	ephemeral *ephemeralKV // nil without Postgres
	// cfg is the host configuration, normalized exactly once at construction
	// (normalizeConfig).
	nameAdmission  func(context.Context, iam.NameAdmissionRequest) error
	cfg            Config
	verifyWarnOnce sync.Once

	// appHTTPClient is the outbound client for application self-registration
	// fetches (application.json, JWKS during signed rotation): the
	// Deps.OutboundHTTP override, else newApplicationsHTTPClient (#264).
	appHTTPClient *http.Client
	// appAdmission is the optional host-injected admission predicate consulted
	// before any registration fetch (#264 anti-squat doctrine: cost gates live
	// in the host — authkit never learns what a credit card is). Nil = allow.
	appAdmission func(ctx context.Context, domain string) error
	// instanceAdmission is the host admission seam for generated persona-
	// instance creation (#263) — mayCreateInstance consults it. Same anti-squat
	// split as appAdmission: authkit owns velocity limits, the host owns cost
	// gates. Nil = allow.
	instanceAdmission func(ctx context.Context, group iam.GroupRef, subject string) error
	// rootGroupID caches the root group id (string) once resolved.
	rootGroupID atomic.Value

	smsHealth smsHealth

	verifier *verify.Verifier
	// published are the documents PublishDocument signed and stored.
	published publishedDocuments
}

// SendWelcome triggers the welcome email if an EmailSender is configured.
func (s *Engine) SendWelcome(ctx context.Context, userID string) {
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

// HasPassword reports whether the user has a local password set.
func (s *Engine) HasPassword(ctx context.Context, userID string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}
	return s.q.UserHasPassword(ctx, userID)
}

// listEntitlements returns current entitlement names for a user (fresh from
// the provider — a one-element batch, #221). A provider failure is logged and
// returned as none — callers (admin user views) degrade rather than fail.
func (s *Engine) listEntitlements(ctx context.Context, userID string) []string {
	provider := s.entitlementsProvider()
	if provider == nil {
		return nil
	}
	m, err := provider.ListEntitlements(ctx, []string{userID})
	if err != nil {
		stdlog.Printf("authkit: error: entitlements provider failed for user %q; reporting no entitlements: %v", userID, err)
		return nil
	}
	return m[userID]
}

// (legacy ChangePassword removed in favor of unified ChangePassword with session revocation)

// --- Pending Registration Helpers ---

// GetPendingRegistrationByEmail looks up a pending registration by email.
func (s *Engine) GetPendingRegistrationByEmail(ctx context.Context, email string) (*authflow.PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, kindRegisterEmail, email)
	if !ok {
		return nil, nil
	}
	return &authflow.PendingRegistration{
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
	}, nil
}

// GetPendingPhoneRegistrationByPhone looks up a pending phone registration by phone number.
// (PendingRegistration.Email carries the phone for phone registrations, preserving prior behavior.)
func (s *Engine) GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*authflow.PendingRegistration, error) {
	if !s.useEphemeralStore() {
		return nil, nil
	}
	rec, ok := s.findPendingChangeByTarget(ctx, kindRegisterPhone, phone)
	if !ok {
		return nil, nil
	}
	return &authflow.PendingRegistration{
		Email:             rec.Target,
		Username:          rec.Username,
		PasswordHash:      rec.PasswordHash,
		PreferredLanguage: rec.PreferredLanguage,
	}, nil
}

// VerifyPendingPassword checks if the provided password matches the pending registration's hash.
// Returns true if password is correct, false otherwise.
func (s *Engine) VerifyPendingPassword(ctx context.Context, email, pass string) bool {
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
func (s *Engine) VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool {
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
func (s *Engine) requirePG() error {
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
