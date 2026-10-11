package engine

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/password"
	"github.com/open-rails/authkit/internal/ratelimit"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
	"github.com/redis/go-redis/v9"
)

// Engine owns local business logic and resources behind Client.
type Engine struct {
	closeOnce sync.Once
	closeErr  error

	maintenance *riverMaintenance
	onEvent     func(context.Context, iam.Event) error
	onPurge     func(context.Context, iam.UserDeletion) error
	// deletionCheck is Deps.DeletionCheck: the host may refuse a self-deletion.
	deletionCheck func(context.Context, string) error
	// eventProducers are insert-only River clients for other issuers' fleets.
	eventProducers sync.Map

	// keys is read per-operation (ActiveSigner/PublicKeys), never snapshotted:
	// a live keys.Source (e.g. the reloadable file source) hot-swaps keys
	// behind an atomic pointer, and the engine must observe every swap (#238).
	keys keys.Source

	// Only resources allocated by New are closed with the client.
	ownedKeySource *keys.FileSource

	providers          []provider.Provider
	email              config.EmailSender
	sms                config.SMSSender
	emailHealth        senderHealth
	smsHealth          senderHealth
	healthMu           sync.Mutex
	stopHealth         context.CancelFunc
	entitlements       func(context.Context, []string) (map[string][]string, error)
	entitlementHolders func(context.Context, string) ([]string, error)
	pg                 *pgxpool.Pool
	q                  *db.Queries
	schema             string       // validated Postgres schema name; db.DefaultSchema when unset
	groupSchema        *rbac.Schema // compiled Config.Roles (nil ⇒ root-only default)
	// oauthGrants is the host's OAuth grant authorizer (Deps.OAuthGrants), nil for the defaults.
	oauthGrants       iam.OAuthGrantAuthorizer
	solanaSNSResolver SolanaSNSResolver
	sns               solanaSNS
	// now is the engine clock for TTL/grace decisions (SetClock).
	now       func() time.Time
	ephemeral *ephemeralKV          // nil without Postgres
	redis     redis.UniversalClient // Deps.Redis: DPoP proofs, else memory
	// smsLimiter spends text messages' send limits (SetSMSLimiter).
	smsLimiter ratelimit.Limiter
	// replays spends JWT-bearer assertions (RFC 7523 §3), in the store DPoP
	// proofs are spent in: Deps.Redis, else memory.
	replays *dpop.Replays
	// resource verifies access tokens for Config.Resource.ID; nil admits
	// none. resourceHosts is Deps.ResourceHosts.
	resource      *resourceServer
	resourceHosts func(ctx context.Context, host string) (bool, error)
	nameAdmission func(context.Context, iam.NameAdmissionRequest) error
	// cfg is the host configuration, normalized once (config.Normalize).
	cfg config.Config
	// rootGroupID caches the root group id (string) once resolved.
	rootGroupID atomic.Value

	auth      *Authenticator
	mfaExempt exemptPaths
	// provisioning are Config.Provisioning's targets.
	provisioning []*provisioningTarget
}

// SendWelcome sends the welcome email when Deps.Email is set.
func (s *Engine) SendWelcome(ctx context.Context, userID string) {
	if s.email == nil || s.pg == nil || strings.TrimSpace(userID) == "" {
		return
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil || u.Email == nil {
		return
	}
	_ = s.sendEmail(ctx, iam.EmailMessage{Kind: iam.MessageWelcome, To: *u.Email, Username: deref(u.Username), Language: s.userLanguage(ctx, userID)})
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
	if s.entitlements == nil {
		return nil
	}
	m, err := s.entitlements(ctx, []string{userID})
	if err != nil {
		stdlog.Printf("authkit: error: entitlements provider failed for user %q; reporting no entitlements: %v", userID, err)
		return nil
	}
	return m[userID]
}

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
	ok, err := password.VerifyArgon2id(ctx, pr.PasswordHash, pass)
	return err == nil && ok
}

// VerifyPendingPhonePassword checks if the provided password matches the pending
// phone registration's hash. Returns true if password is correct, false otherwise.
func (s *Engine) VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool {
	pr, err := s.GetPendingPhoneRegistrationByPhone(ctx, phone)
	if err != nil || pr == nil {
		return false
	}
	ok, err := password.VerifyArgon2id(ctx, pr.PasswordHash, pass)
	return err == nil && ok
}

// requirePG returns an error when no Postgres pool is configured (verify-only /
// config-only construction). Store-backed methods guard on it.
func (s *Engine) requirePG() error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	return nil
}
