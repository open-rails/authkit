package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	stdlog "log"
	"os"
	"sort"
	"strings"
	"time"

	entpg "github.com/PaulFidika/authkit/entitlements"
	jwtkit "github.com/PaulFidika/authkit/jwt"
	"github.com/PaulFidika/authkit/password"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configures issued tokens and identifiers.
type Options struct {
	Issuer          string
	IssuedAudiences []string // JWT audiences - tokens issued will contain ALL of these audiences
	// ExpectedAudiences enforces that verified access tokens contain at least one
	// of these audiences. Prefer this over ExpectedAudience for new integrations.
	ExpectedAudiences []string
	// ExpectedAudience enforces a single required audience for verified access tokens.
	// Deprecated: prefer ExpectedAudiences.
	ExpectedAudience     string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	SessionMaxPerUser    int
	// Optional link building (paths are fixed: /reset and /verify)
	BaseURL string
}

// Keyset holds the active signer and the public keys exposed via JWKS.
type Keyset struct {
	Active     jwtkit.Signer
	PublicKeys map[string]*rsa.PublicKey // kid -> pub
}

// EntitlementsProvider returns application entitlements for a user (e.g., billing tiers).
type EntitlementsProvider interface {
	ListEntitlements(ctx context.Context, userID string) ([]entpg.Entitlement, error)
}

// (storage layer collapsed into direct Postgres/Redis helpers)

// Service is the core auth service used by HTTP adapters.
type Service struct {
	opts           Options
	keys           Keyset
	email          EmailSender
	sms            SMSSender
	pg             *pgxpool.Pool
	entitlements   EntitlementsProvider
	authlog        AuthEventLogger
	ephemeralStore EphemeralStore
	ephemeralMode  EphemeralMode
}

func NewService(opts Options, keys Keyset) *Service {
	return &Service{opts: opts, keys: keys, ephemeralMode: EphemeralMemory}
}

// NewFromConfig creates a Service from high-level Config + Stores.
// If Keys is nil, auto-discovers keys from environment variables, filesystem, or generates development keys.
func NewFromConfig(cfg Config) (*Service, error) {
	// Handle nil Keys - auto-discover from env vars, /vault/auth/keys.json, or generate for dev
	keySource := cfg.Keys
	if keySource == nil {
		var err error
		keySource, err = jwtkit.NewAutoKeySource()
		if err != nil {
			return nil, fmt.Errorf("authkit: failed to auto-discover JWT keys: %w", err)
		}
	}

	ks := Keyset{Active: keySource.ActiveSigner(), PublicKeys: keySource.PublicKeys()}

	// Require critical JWT configuration
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authkit: Issuer is required (e.g., \"https://myapp.com\")")
	}
	issuedAudiences := cfg.IssuedAudiences
	if len(issuedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: IssuedAudiences is required (e.g., []string{\"myapp\", \"billing-app\"})")
	}
	expectedAudience := strings.TrimSpace(cfg.ExpectedAudience)
	expectedAudiences := cfg.ExpectedAudiences
	if len(expectedAudiences) == 0 && expectedAudience != "" {
		expectedAudiences = []string{expectedAudience}
	}
	if len(expectedAudiences) == 0 {
		return nil, fmt.Errorf("authkit: ExpectedAudiences (or ExpectedAudience) is required (e.g., []string{\"myapp\"})")
	}

	maxSess := cfg.SessionMaxPerUser
	if maxSess == 0 {
		maxSess = 3
	}
	accessTTL := cfg.AccessTokenDuration
	if accessTTL == 0 {
		accessTTL = time.Hour
	}
	refTTL := cfg.RefreshTokenDuration // 0 or less => indefinite sessions
	opts := Options{
		Issuer:               cfg.Issuer,
		IssuedAudiences:      issuedAudiences,
		ExpectedAudiences:    expectedAudiences,
		ExpectedAudience:     expectedAudiences[0],
		AccessTokenDuration:  accessTTL,
		RefreshTokenDuration: refTTL,
		SessionMaxPerUser:    maxSess,
		BaseURL:              cfg.BaseURL,
	}
	return NewService(opts, ks), nil
}

// JWKS returns a JWKS built from configured public keys.
func (s *Service) JWKS() jwtkit.JWKS {
	// Build a deterministic, sorted JWKS and omit alg to avoid incorrect
	// per-key algorithm when multiple algorithms are in rotation.
	ks := jwtkit.JWKS{Keys: make([]jwtkit.JWK, 0, len(s.keys.PublicKeys))}
	kids := make([]string, 0, len(s.keys.PublicKeys))
	for kid := range s.keys.PublicKeys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		pub := s.keys.PublicKeys[kid]
		ks.Keys = append(ks.Keys, jwtkit.RSAPublicToJWK(pub, kid, ""))
	}
	return ks
}

// IssueAccessToken builds and signs an access token (JWT) for the given user.
// Includes core registered claims plus:
// - roles (snapshot)
// - entitlements (snapshot)
// - email, username, discord_username (if available)
// Extra claims in `extra` are merged into the token body (e.g., sid).
func (s *Service) IssueAccessToken(ctx context.Context, userID, email string, extra map[string]any) (token string, expiresAt time.Time, err error) {
	base := jwtkit.BaseRegisteredClaims(userID, s.opts.IssuedAudiences, s.opts.AccessTokenDuration)
	expiresAt = base.ExpiresAt.Time
	var roles []string
	if s.pg != nil {
		roles = s.listRoleSlugsByUser(ctx, userID)
	}
	var ents []string
	if s.entitlements != nil {
		if details, err := s.entitlements.ListEntitlements(ctx, userID); err == nil {
			for _, d := range details {
				ents = append(ents, d.Name)
			}
		}
	}
	// Attempt to fetch username/email fresh from DB if possible
	var username *string
	var emailVerified bool
	if s.pg != nil {
		if u, uErr := s.getUserByID(ctx, userID); uErr == nil && u != nil {
			if u.Email != nil && *u.Email != "" {
				email = *u.Email
			}
			username = u.Username
			emailVerified = u.EmailVerified
		}
	}
	// Best-effort fetch of discord username (prefer profiles.users.discord_username; fallback to provider profile)
	var discord string
	if du, duErr := s.getDiscordUsername(ctx, userID); duErr == nil {
		discord = du
	}

	claims := map[string]any{
		"iss": s.opts.Issuer,
		"sub": base.Subject,
		"aud": base.Audience,
		"iat": base.IssuedAt.Time.Unix(),
		"exp": base.ExpiresAt.Time.Unix(),
		// identity and profile snapshots for convenience
		"email":            email,
		"email_verified":   emailVerified,
		"username":         username,
		"discord_username": discord,
		"roles":            roles,
		"entitlements":     ents,
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok, err := s.keys.Active.Sign(ctx, claims)
	return tok, expiresAt, err
}

// --- Refresh tokens are implemented via server-side sessions in service_sessions.go ---

func newUUID() string { return strings.ReplaceAll(randB64(16), "-", "") }

// Options exposes immutable configuration for callers that need to validate claims.
func (s *Service) Options() Options { return s.opts }

// WithPostgres attaches a pgx pool to the service.
func (s *Service) WithPostgres(pool *pgxpool.Pool) *Service { s.pg = pool; return s }

// Postgres returns the attached pgx pool (may be nil).
func (s *Service) Postgres() *pgxpool.Pool { return s.pg }

// WithEntitlements sets the entitlements provider.
func (s *Service) WithEntitlements(p EntitlementsProvider) *Service { s.entitlements = p; return s }

// WithAuthLogger sets the authentication event logger (e.g., ClickHouse sink).
func (s *Service) WithAuthLogger(l AuthEventLogger) *Service { s.authlog = l; return s }

// Keyfunc looks up a public key by KID, falling back to the active key if missing.
func (s *Service) Keyfunc() func(token *jwt.Token) (any, error) {
	return func(token *jwt.Token) (any, error) {
		if kid, _ := token.Header["kid"].(string); kid != "" {
			if pub, ok := s.keys.PublicKeys[kid]; ok {
				return pub, nil
			}
		}
		// Fallback: active signer public key (works when only one key is used)
		if rsaSigner, ok := s.keys.Active.(*jwtkit.RSASigner); ok {
			return rsaSigner.PublicKey(), nil
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

// RequestPhoneChange initiates a phone number change by sending a verification code to the new phone.
// The current phone is NOT changed until the user confirms via ConfirmPhoneChange.
func (s *Service) RequestPhoneChange(ctx context.Context, userID, newPhone string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	trimmed := strings.TrimSpace(newPhone)
	if trimmed == "" {
		return fmt.Errorf("phone required")
	}

	// Get user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// Check if trying to change to the same phone
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, trimmed) {
		return fmt.Errorf("new phone is the same as current phone")
	}

	// Check if new phone is already in use by another user
	existing, _ := s.getUserByPhone(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("phone already in use")
	}

	// Generate 6-digit numeric code
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	// TTL for phone change is 24 hours (longer than regular verification)
	ttl := 24 * time.Hour

	// Store phone verification with purpose "change_phone" keyed by userID
	if err := s.storePhoneVerification(ctx, "change_phone", trimmed, userID, hash, ttl); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send verification code to new phone
	if s.sms != nil {
		_ = s.sms.SendVerificationCode(ctx, trimmed, code)
	} else {
		stdlog.Printf("[authkit/dev-sms] phone change verify to=%s username=%s code=%s", trimmed, username, code)
	}

	// Optionally: notify old phone (not implemented)

	return nil
}

// ConfirmPhoneChange verifies the code and updates the user's phone number.
// This is called when the user enters the verification code sent to their new phone.
func (s *Service) ConfirmPhoneChange(ctx context.Context, userID, phone, code string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}

	// Use consumePhoneVerification to validate and consume the code, keyed by userID
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		_, err := s.consumePhoneVerification(ctx, "change_phone", phone, hash)
		if err != nil {
			return jwt.ErrTokenUnverifiable
		}
	} else {
		return jwt.ErrTokenUnverifiable
	}

	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return errOrUnauthorized(err)
	}

	// Check if the phone is different from current phone (it's a change)
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, phone) {
		// Same phone - just verify it
		return s.setPhoneVerified(ctx, userID, true)
	}

	// Different phone - this is a phone change request
	_, err = s.pg.Exec(ctx, `UPDATE profiles.users SET phone_number=$2, phone_verified=true, updated_at=NOW() WHERE id=$1`, userID, phone)
	if err != nil {
		return err
	}

	return nil
}

// ResendPhoneChangeCode resends the verification code for a pending phone change.
func (s *Service) ResendPhoneChangeCode(ctx context.Context, userID, phone string) error {
	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// Check if pending phone is different from current (it's a change request, not just verification)
	if u.PhoneNumber != nil && strings.EqualFold(*u.PhoneNumber, phone) {
		return fmt.Errorf("no pending phone change found")
	}

	// Check if pending phone change exists (by userID)
	var data phoneVerificationData
	ok, _ := s.ephemGetJSON(ctx, s.phoneVerificationKey("change_phone", phone), &data)
	if !ok || data.UserID != userID {
		return fmt.Errorf("no pending phone change found")
	}

	// Generate new code
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	ttl := 24 * time.Hour

	// Store new phone verification (by userID)
	if err := s.storePhoneVerification(ctx, "change_phone", phone, userID, hash, ttl); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send new code
	if s.sms != nil {
		_ = s.sms.SendVerificationCode(ctx, phone, code)
	} else {
		stdlog.Printf("[authkit/dev-sms] phone change resend to=%s username=%s code=%s", phone, username, code)
	}

	return nil
}

// getUserByPhone returns a user by phone number (if any)
func (s *Service) getUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT id, email, phone_number, username, discord_username, email_verified, phone_verified, is_active, deleted_at, biography, created_at, updated_at, last_login FROM profiles.users WHERE phone_number=$1`, phone)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PhoneNumber, &u.Username, &u.DiscordUsername, &u.EmailVerified, &u.PhoneVerified, &u.IsActive, &u.DeletedAt, &u.Biography, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	return &u, nil
}

// setPhoneVerified sets the phone_verified flag for a user.
func (s *Service) setPhoneVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET phone_verified=$2, updated_at=NOW() WHERE id=$1`, id, v)
	return err
}

// SendPhone2FASetupCode generates and sends a 6-digit code for 2FA setup to the user's phone.
func (s *Service) SendPhone2FASetupCode(ctx context.Context, userID, phone, code string) error {
	hash := sha256Hex(code)
	// Store code in ephemeral store for 10 minutes, purpose: "2fa_setup"
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "2fa_setup", phone, userID, hash, 10*time.Minute); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ephemeral store not configured")
	}

	if s.sms != nil {
		return s.sms.SendVerificationCode(ctx, phone, code)
	}
	// In production, require SMS to be configured
	if !isDevEnvironment(getEnvironment()) {
		return fmt.Errorf("SMS sender not configured")
	}
	// Dev mode: log code to stdout
	stdlog.Printf("[authkit/dev-sms] 2FA setup phone=%s code= %s", phone, code)
	return nil
}

// VerifyPhone2FASetupCode checks the code for 2FA phone setup.
func (s *Service) VerifyPhone2FASetupCode(ctx context.Context, userID, phone, code string) (bool, error) {
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "2fa_setup", phone, hash)
		if err != nil {
			return false, err
		}
		if uid != userID {
			return false, fmt.Errorf("user_id mismatch")
		}
		return true, nil
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

// PasswordLogin verifies credentials and issues an ID token.
func (s *Service) PasswordLogin(ctx context.Context, email, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil || !u.IsActive {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	// Support legacy bcrypt with lazy rehash to Argon2id on successful login.
	switch algo {
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
	case "bcrypt", "":
		// Some legacy rows may have empty algo but bcrypt formatted hash ($2b$...) — accept those too.
		if !password.IsBcryptHash(hash) && algo == "" {
			return "", time.Time{}, errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
		// Rehash to Argon2id and upsert
		phc, err := password.HashArgon2id(pass)
		if err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return "", time.Time{}, errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	emailStr := ""
	if u.Email != nil {
		emailStr = *u.Email
	}
	return s.IssueAccessToken(ctx, u.ID, emailStr, extra)
}

// PasswordLoginByUserID verifies credentials for a specific user ID and issues an ID token.
// This supports login flows where the identifier is a phone number or username and email may be NULL.
func (s *Service) PasswordLoginByUserID(ctx context.Context, userID, pass string, extra map[string]any) (string, time.Time, error) {
	if s.pg == nil {
		return "", time.Time{}, jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return "", time.Time{}, jwt.ErrTokenInvalidClaims
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil || !u.IsActive {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	hash, algo, _, err := s.getPasswordHash(ctx, u.ID)
	if err != nil {
		return "", time.Time{}, errOrUnauthorized(err)
	}
	switch algo {
	case "argon2id":
		ok, err := password.VerifyArgon2id(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
	case "bcrypt", "":
		if !password.IsBcryptHash(hash) && algo == "" {
			return "", time.Time{}, errOrUnauthorized(nil)
		}
		ok, err := password.VerifyBcrypt(hash, pass)
		if err != nil || !ok {
			return "", time.Time{}, errOrUnauthorized(err)
		}
		// Rehash to Argon2id and upsert
		phc, err := password.HashArgon2id(pass)
		if err == nil {
			_ = s.upsertPasswordHash(ctx, u.ID, phc, "argon2id", nil)
		}
	default:
		return "", time.Time{}, errOrUnauthorized(nil)
	}
	_ = s.setLastLogin(ctx, u.ID, time.Now())
	emailStr := ""
	if u.Email != nil {
		emailStr = *u.Email
	}
	return s.IssueAccessToken(ctx, u.ID, emailStr, extra)
}

func errOrUnauthorized(err error) error {
	if err != nil {
		return err
	}
	return jwt.ErrTokenInvalidClaims
}

// ChangePassword sets or changes a user's password.
// If the user already has a password, current must verify; otherwise current is ignored.
// Always Argon2id-hashes the new password and upserts it, then revokes all
// other sessions for the user; caller may keep one active session via keepSessionID.
func (s *Service) ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if err := password.Validate(new); err != nil {
		return err
	}
	// If a password exists, verify current
	hadPassword := s.hasPassword(ctx, userID)
	if hadPassword {
		hash, algo, _, err := s.getPasswordHash(ctx, userID)
		if err != nil {
			return err
		}
		switch algo {
		case "argon2id":
			ok, err := password.VerifyArgon2id(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		case "bcrypt", "":
			if !password.IsBcryptHash(hash) && algo == "" {
				return jwt.ErrTokenInvalidClaims
			}
			ok, err := password.VerifyBcrypt(hash, current)
			if err != nil || !ok {
				return jwt.ErrTokenInvalidClaims
			}
		default:
			return jwt.ErrTokenInvalidClaims
		}
	}
	// Hash and store new password
	phc, err := password.HashArgon2id(new)
	if err != nil {
		return err
	}
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return err
	}
	// Revoke all other sessions after a successful password change to ensure that
	// any previously compromised refresh tokens are invalidated. The current
	// session can be preserved via keepSessionID if provided.
	if err := s.RevokeAllSessions(ctx, userID, keepSessionID); err != nil {
		return err
	}
	return nil
}

// EmailSender sends password reset emails.
type EmailSender interface {
	// SendPasswordResetCode sends a password reset code to the user's email with personalization.
	// AuthKit looks up the user's current email and username before calling this.
	SendPasswordResetCode(ctx context.Context, email, username, code string) error

	// SendEmailVerificationCode sends an email verification code to the given email address and username.
	// User doesn't exist yet, so email and username are provided directly for personalization.
	SendEmailVerificationCode(ctx context.Context, email, username, code string) error

	// SendLoginCode sends a two-factor authentication code to the user's email during login.
	// AuthKit looks up the user's email and username before calling this.
	SendLoginCode(ctx context.Context, email, username, code string) error

	// SendWelcome sends a welcome email to the user's email with personalization.
	// AuthKit looks up the user's email and username before calling this.
	SendWelcome(ctx context.Context, email, username string) error
}

// SMSSender sends verification and 2FA codes via SMS.
type SMSSender interface {
	SendVerificationCode(ctx context.Context, phone, code string) error
	SendLoginCode(ctx context.Context, phone, code string) error
}

// WithEmailSender sets the email sender dependency.
func (s *Service) WithEmailSender(sender EmailSender) *Service { s.email = sender; return s }

// WithSMSSender sets the SMS sender dependency.
func (s *Service) WithSMSSender(sender SMSSender) *Service { s.sms = sender; return s }

// HasEmailSender returns true if an email sender is configured.
func (s *Service) HasEmailSender() bool { return s.email != nil }

// HasSMSSender returns true if an SMS sender is configured.
func (s *Service) HasSMSSender() bool { return s.sms != nil }

// RequestPasswordReset creates a reset code and dispatches email. Always returns 202-like behavior.
func (s *Service) RequestPasswordReset(ctx context.Context, email string, ttl time.Duration) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute // Shorter TTL for 6-digit codes (was 1 hour for long tokens)
	}
	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	if err := s.createResetToken(ctx, u.ID, hash, time.Now().Add(ttl)); err != nil {
		return nil
	}
	if u.Email != nil {
		username := ""
		if u.Username != nil {
			username = *u.Username
		}
		if s.email != nil {
			_ = s.email.SendPasswordResetCode(ctx, *u.Email, username, code)
		} else {
			stdlog.Printf("[authkit/dev-email] password reset email=%s username=%s code=%s", *u.Email, username, code)
		}
	}
	return nil
}

// ConfirmPasswordReset verifies token and sets a new password.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rt, err := s.useResetToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	phc, err := password.HashArgon2id(newPassword)
	if err != nil {
		return "", err
	}
	if err := s.upsertPasswordHash(ctx, rt.UserID, phc, "argon2id", nil); err != nil {
		return "", err
	}
	// Do not revoke existing sessions on reset per host policy.
	return rt.UserID, nil
}

// RequestEmailVerification creates a verification code and dispatches an email. Always returns 202-like behavior.
func (s *Service) RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.getUserByEmail(ctx, email)
	if err != nil || u == nil {
		return nil
	}
	if u.EmailVerified {
		return nil
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute // Shorter TTL for 6-digit codes (was 24 hours for long tokens)
	}
	if u.Email == nil {
		return nil // Can't verify a NULL email
	}
	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	if err := s.createEmailVerifyToken(ctx, u.ID, hash, *u.Email, time.Now().Add(ttl)); err != nil {
		return nil
	}
	username := ""
	if u.Username != nil {
		username = *u.Username
	}
	if s.email != nil {
		_ = s.email.SendEmailVerificationCode(ctx, *u.Email, username, code)
	} else {
		stdlog.Printf("[authkit/dev-email] email verify to=%s username=%s code=%s", *u.Email, username, code)
	}
	return nil
}

// ConfirmEmailVerification verifies a token and marks email_verified = true.
// Returns the userID of the verified user.
func (s *Service) ConfirmEmailVerification(ctx context.Context, token string) (userID string, err error) {
	if s.pg == nil {
		return "", jwt.ErrTokenUnverifiable
	}
	rec, err := s.useEmailVerifyToken(ctx, sha256Hex(token))
	if err != nil {
		return "", err
	}
	// Ensure the token verifies the same email currently on the account.
	// Backward-compat: if the stored email is NULL (old tokens), accept as account-level verify.
	u, err := s.getUserByID(ctx, rec.UserID)
	if err != nil || u == nil {
		return "", errOrUnauthorized(err)
	}
	if rec.Email != nil && u.Email != nil && !strings.EqualFold(*u.Email, *rec.Email) {
		// Email changed since request; treat token as consumed but invalid for current address
		return "", jwt.ErrTokenInvalidClaims
	}
	err = s.setEmailVerified(ctx, rec.UserID, true)
	if err != nil {
		return "", err
	}
	return rec.UserID, nil
}

// --- Pending Registration (for email/password signups) ---

// CreatePendingRegistration creates a pending registration and sends verification email.
// Returns token for verification. Allows duplicate pending registrations (last one wins).
func (s *Service) CreatePendingRegistration(ctx context.Context, email, username, passwordHash string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	// Generate 6-character alphanumeric verification code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		if err := s.storePendingRegistration(ctx, email, username, passwordHash, hash, ttl); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("ephemeral store not configured")
	}

	// Send verification email with code
	if s.email != nil {
		_ = s.email.SendEmailVerificationCode(ctx, email, username, code)
	} else {
		stdlog.Printf("[authkit/dev-email] verify pending registration to=%s username=%s code=%s", email, username, code)
	}

	return code, nil
}

// ConfirmPendingRegistration verifies token and creates the actual user account.
// This implements "first to verify wins" - whoever verifies first gets the username/email.
func (s *Service) ConfirmPendingRegistration(ctx context.Context, token string) (userID string, err error) {
	hash := sha256Hex(token)

	var email, username, passwordHash string
	if s.useEphemeralStore() {
		data, ok, err := s.loadPendingRegistration(ctx, hash)
		if err != nil || !ok {
			return "", jwt.ErrTokenUnverifiable
		}
		email, username, passwordHash = data.Email, data.Username, data.PasswordHash
	} else {
		return "", jwt.ErrTokenUnverifiable
	}

	// Check if email or username is now taken (someone else verified first)
	var exists bool
	err = s.pg.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM profiles.users
			WHERE email = lower($1) OR username = $2
		)
	`, email, username).Scan(&exists)

	if err != nil {
		return "", err
	}

	if exists {
		// Someone else got there first - delete this pending registration
		if s.useEphemeralStore() {
			s.deletePendingRegistration(ctx, hash, pendingRegistrationData{Email: email, Username: username})
		}
		return "", fmt.Errorf("email or username already taken")
	}

	// Create the actual user (email_verified = true from the start)
	var uid string
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.users (email, username, email_verified)
		VALUES (lower($1), $2, true)
		RETURNING id::text
	`, email, username).Scan(&uid)

	if err != nil {
		return "", err
	}

	// Set password
	_, err = s.pg.Exec(ctx, `
		INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo)
		VALUES ($1, $2, 'argon2id')
	`, uid, passwordHash)

	if err != nil {
		return "", err
	}

	// Delete pending registration (success)
	if s.useEphemeralStore() {
		s.deletePendingRegistration(ctx, hash, pendingRegistrationData{Email: email, Username: username})
	}

	return uid, nil
}

// CheckPendingRegistrationConflict checks if email or username exists in users or pending registration cache.
// Returns (emailTaken, usernameTaken, error)
func (s *Service) CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error) {
	var emailTaken, usernameTaken bool
	if s.pg != nil {
		err := s.pg.QueryRow(ctx, `
			SELECT
				EXISTS(SELECT 1 FROM profiles.users WHERE email = lower($1)),
				EXISTS(SELECT 1 FROM profiles.users WHERE username = $2)
		`, email, username).Scan(&emailTaken, &usernameTaken)
		if err != nil {
			return false, false, err
		}
	}

	if emailTaken || usernameTaken {
		return emailTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if v, ok, _ := s.ephemGetString(ctx, keyPendingRegEmail+normalizeEmail(email)); ok && v != "" {
			emailTaken = true
		}
		if v, ok, _ := s.ephemGetString(ctx, keyPendingRegUser+username); ok && v != "" {
			usernameTaken = true
		}
		return emailTaken, usernameTaken, nil
	}
	return emailTaken, usernameTaken, nil
}

// --- Phone Registration (for phone+password signups) ---

// CreatePendingPhoneRegistration creates a pending phone registration and sends SMS verification code.
// Returns 6-digit code for verification. Code expires in 10 minutes (shorter than email).
func (s *Service) CreatePendingPhoneRegistration(ctx context.Context, phone, username, passwordHash string) (string, error) {
	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		if err := s.storePendingPhoneRegistration(ctx, phone, username, passwordHash, hash, 15*time.Minute); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("ephemeral store not configured")
	}

	// Send SMS
	if s.sms != nil {
		_ = s.sms.SendVerificationCode(ctx, phone, code)
	} else {
		// In production, require SMS to be configured
		if !isDevEnvironment(getEnvironment()) {
			return "", fmt.Errorf("SMS verification unavailable: Twilio not configured (phone registration requires SMS in production)")
		}
		// Dev mode: log code to stdout
		stdlog.Printf("[authkit/dev-sms] verify pending phone registration phone=%s code=%s", phone, code)
	}

	return code, nil
}

// ConfirmPendingPhoneRegistration verifies code and creates the actual user account.
// Implements "first to verify wins" - whoever verifies first gets the username/phone.
func (s *Service) ConfirmPendingPhoneRegistration(ctx context.Context, phone, code string) (userID string, err error) {
	hash := sha256Hex(code)

	var username, passwordHash string
	if s.useEphemeralStore() {
		tokenHash, ok, err := s.ephemGetString(ctx, keyPendingPhonePhone+phone)
		if err != nil || !ok || tokenHash == "" || tokenHash != hash {
			return "", jwt.ErrTokenUnverifiable
		}
		data, ok, err := s.loadPendingPhoneRegistration(ctx, tokenHash)
		if err != nil || !ok {
			return "", jwt.ErrTokenUnverifiable
		}
		username, passwordHash = data.Username, data.PasswordHash
	} else {
		return "", jwt.ErrTokenUnverifiable
	}

	// Check if phone or username is now taken
	var exists bool
	err = s.pg.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM profiles.users
			WHERE phone_number = $1 OR username = $2
		)
	`, phone, username).Scan(&exists)

	if err != nil {
		return "", err
	}

	if exists {
		// Someone else got there first
		if s.useEphemeralStore() {
			s.deletePendingPhoneRegistration(ctx, hash, pendingRegistrationData{Email: phone, Username: username})
		}
		return "", fmt.Errorf("phone or username already taken")
	}

	// Create the actual user (phone_verified = true from the start, email = NULL)
	var uid string
	err = s.pg.QueryRow(ctx, `
		INSERT INTO profiles.users (phone_number, username, phone_verified, email_verified)
		VALUES ($1, $2, true, false)
		RETURNING id::text
	`, phone, username).Scan(&uid)

	if err != nil {
		return "", err
	}

	// Set password
	_, err = s.pg.Exec(ctx, `
		INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo)
		VALUES ($1, $2, 'argon2id')
	`, uid, passwordHash)

	if err != nil {
		return "", err
	}

	// Delete pending registration
	if s.useEphemeralStore() {
		s.deletePendingPhoneRegistration(ctx, hash, pendingRegistrationData{Email: phone, Username: username})
	}

	return uid, nil
}

// CheckPhoneRegistrationConflict checks if phone or username exists in users OR pending tables.
// Returns (phoneTaken, usernameTaken, error)
func (s *Service) CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error) {
	var phoneTaken, usernameTaken bool

	if s.pg != nil {
		err := s.pg.QueryRow(ctx, `
			SELECT
				EXISTS(SELECT 1 FROM profiles.users WHERE phone_number = $1),
				EXISTS(SELECT 1 FROM profiles.users WHERE username = $2)
		`, phone, username).Scan(&phoneTaken, &usernameTaken)
		if err != nil {
			return false, false, err
		}
	}

	if phoneTaken || usernameTaken {
		return phoneTaken, usernameTaken, nil
	}

	if s.useEphemeralStore() {
		if v, ok, _ := s.ephemGetString(ctx, keyPendingPhonePhone+phone); ok && v != "" {
			phoneTaken = true
		}
		if v, ok, _ := s.ephemGetString(ctx, keyPendingPhoneUser+username); ok && v != "" {
			usernameTaken = true
		}
		return phoneTaken, usernameTaken, nil
	}
	return phoneTaken, usernameTaken, nil
}

// GetUserByPhone looks up a user by phone number.
func (s *Service) GetUserByPhone(ctx context.Context, phone string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	row := s.pg.QueryRow(ctx, `
		SELECT id, email, phone_number, username, discord_username, email_verified, phone_verified, is_active, deleted_at, biography, created_at, updated_at, last_login
		FROM profiles.users WHERE phone_number = $1
	`, phone)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PhoneNumber, &u.Username, &u.DiscordUsername, &u.EmailVerified, &u.PhoneVerified, &u.IsActive, &u.DeletedAt, &u.Biography, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	return &u, nil
}

// --- Phone Verification (for existing users with unverified phones) ---

// RequestPhoneVerification looks up the user by phone number and sends a verification code.
// This mirrors the RequestEmailVerification pattern - caller only needs to provide the phone number.
// Always returns nil for security (prevents phone enumeration).
func (s *Service) RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error {
	if s.pg == nil {
		return nil
	}
	u, err := s.GetUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Fail silently
	}
	if u.PhoneVerified {
		return nil // Already verified
	}
	if u.PhoneNumber == nil {
		return nil // No phone number set
	}
	return s.SendPhoneVerificationToUser(ctx, *u.PhoneNumber, u.ID, ttl)
}

// SendPhoneVerificationToUser creates a verification code and sends it via SMS to a known user.
// Use RequestPhoneVerification if you only have a phone number and need to look up the user.
// Always returns nil for security.
func (s *Service) SendPhoneVerificationToUser(ctx context.Context, phone, userID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "verify_phone", phone, userID, hash, ttl); err != nil {
			return nil
		}
	} else {
		return nil
	}

	// Send SMS
	if s.sms != nil {
		_ = s.sms.SendVerificationCode(ctx, phone, code)
	} else {
		// In production, require SMS to be configured
		if !isDevEnvironment(getEnvironment()) {
			return fmt.Errorf("SMS verification unavailable: Twilio not configured (phone verification requires SMS in production)")
		}
		// Dev mode: log code to stdout
		stdlog.Printf("[authkit/dev-sms] phone verify phone=%s code=%s", phone, code)
	}

	return nil
}

// ConfirmPhoneVerification verifies a token and marks phone_verified = true.
func (s *Service) ConfirmPhoneVerification(ctx context.Context, phone, code string) error {
	hash := sha256Hex(code)

	var userID string
	var err error
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "verify_phone", phone, hash)
		if err != nil {
			return err
		}
		userID = uid
	} else {
		return jwt.ErrTokenUnverifiable
	}

	// Mark phone as verified
	_, err = s.pg.Exec(ctx, `
		UPDATE profiles.users 
		SET phone_verified = true 
		WHERE id = $1 AND phone_number = $2
	`, userID, phone)

	return err
}

// --- Phone Password Reset (for phone+password users) ---

// RequestPhonePasswordReset creates a verification code and sends it via SMS.
// Always returns nil to prevent user enumeration (202-like behavior).
func (s *Service) RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration) error {
	// Look up user by phone
	u, err := s.GetUserByPhone(ctx, phone)
	if err != nil || u == nil {
		return nil // Don't reveal if phone exists
	}

	if ttl <= 0 {
		ttl = 15 * time.Minute // Shorter than old email tokens (15 min vs 1 hour)
	}

	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	if s.useEphemeralStore() {
		if err := s.storePhoneVerification(ctx, "password_reset", phone, u.ID, hash, ttl); err != nil {
			return nil
		}
	} else {
		return nil
	}

	// Send SMS
	if s.sms != nil {
		_ = s.sms.SendVerificationCode(ctx, phone, code)
	} else {
		// In production, require SMS to be configured
		if !isDevEnvironment(getEnvironment()) {
			return fmt.Errorf("SMS password reset unavailable: Twilio not configured (phone password reset requires SMS in production)")
		}
		// Dev mode: log code to stdout
		stdlog.Printf("[authkit/dev-sms] password reset phone=%s code=%s", phone, code)
	}

	return nil
}

// ConfirmPhonePasswordReset verifies the code and sets a new password.
func (s *Service) ConfirmPhonePasswordReset(ctx context.Context, phone, code, newPassword string) (string, error) {
	hash := sha256Hex(code)

	var userID string
	if s.useEphemeralStore() {
		uid, err := s.consumePhoneVerification(ctx, "password_reset", phone, hash)
		if err != nil {
			return "", err
		}
		userID = uid
	} else {
		return "", jwt.ErrTokenUnverifiable
	}

	// Hash new password
	phc, err := password.HashArgon2id(newPassword)
	if err != nil {
		return "", err
	}

	// Update password
	if err := s.upsertPasswordHash(ctx, userID, phc, "argon2id", nil); err != nil {
		return "", err
	}

	// Do not revoke existing sessions on reset (same policy as email reset)
	return userID, nil
}

// helpers
func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randInt(max int) int {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	n := int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
	if n < 0 {
		n = -n
	}
	return n % max
}

// randAlphanumeric generates a random numeric code of length n (for Twilio Verify compatibility).
// Changed from alphanumeric to numeric for better UX (easier to type, works with voice channel).
// Security is equivalent when combined with Twilio Verify's rate limiting and fraud protection.
func randAlphanumeric(n int) string {
	// Generate n-digit numeric code (e.g., 6 digits = 000000-999999)
	code := ""
	for i := 0; i < n; i++ {
		code += string('0' + byte(randInt(10)))
	}
	return code
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// --- Direct Postgres helpers (profiles schema) ---

type User struct {
	ID              string
	Email           *string // Nullable - phone-only users have NULL email
	PhoneNumber     *string
	Username        *string
	DiscordUsername *string
	EmailVerified   bool
	PhoneVerified   bool
	IsActive        bool
	DeletedAt       *time.Time
	Biography       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLogin       *time.Time
}

func (s *Service) getUserByEmail(ctx context.Context, email string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT id, email, phone_number, username, discord_username, email_verified, phone_verified, is_active, deleted_at, biography, created_at, updated_at, last_login FROM profiles.users WHERE lower(email)=lower($1)`, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PhoneNumber, &u.Username, &u.DiscordUsername, &u.EmailVerified, &u.PhoneVerified, &u.IsActive, &u.DeletedAt, &u.Biography, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) getUserByUsername(ctx context.Context, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT id, email, phone_number, username, discord_username, email_verified, phone_verified, is_active, deleted_at, biography, created_at, updated_at, last_login FROM profiles.users WHERE username=$1`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PhoneNumber, &u.Username, &u.DiscordUsername, &u.EmailVerified, &u.PhoneVerified, &u.IsActive, &u.DeletedAt, &u.Biography, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) getUserByID(ctx context.Context, id string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT id, email, phone_number, username, discord_username, email_verified, phone_verified, is_active, deleted_at, biography, created_at, updated_at, last_login FROM profiles.users WHERE id=$1`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PhoneNumber, &u.Username, &u.DiscordUsername, &u.EmailVerified, &u.PhoneVerified, &u.IsActive, &u.DeletedAt, &u.Biography, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) createUser(ctx context.Context, email, username string) (*User, error) {
	if s.pg == nil {
		return nil, nil
	}
	// Convert empty email to NULL for database (allows multiple users without emails)
	row := s.pg.QueryRow(ctx, `INSERT INTO profiles.users (email, username) VALUES (NULLIF(lower($1), ''), $2) RETURNING id, email, username, email_verified, is_active`, email, username)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Username, &u.EmailVerified, &u.IsActive); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) setEmailVerified(ctx context.Context, id string, v bool) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET email_verified=$2, updated_at=NOW() WHERE id=$1`, id, v)
	return err
}

func (s *Service) setLastLogin(ctx context.Context, id string, t time.Time) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET last_login=$2, updated_at=NOW() WHERE id=$1`, id, t)
	return err
}

func (s *Service) setActive(ctx context.Context, id string, active bool) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET is_active=$2, updated_at=NOW() WHERE id=$1`, id, active)
	return err
}

// SoftDeleteUser marks the user inactive and sets deleted_at without dropping rows.
// Also revokes all refresh sessions for this issuer.
func (s *Service) SoftDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke sessions first
	_ = s.RevokeAllSessions(ctx, id, nil)
	// Soft-delete user
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET is_active=false, deleted_at=now(), updated_at=now() WHERE id=$1`, id)
	return err
}

// HostDeleteUser performs deletion on behalf of the host application.
// If soft is true, it performs a soft delete (see SoftDeleteUser). If false, it hard-deletes the user
// and all dependent rows via ON DELETE CASCADE.
func (s *Service) HostDeleteUser(ctx context.Context, id string, soft bool) error {
	if soft {
		return s.SoftDeleteUser(ctx, id)
	}
	return s.AdminDeleteUser(ctx, id)
}

func (s *Service) updateUsername(ctx context.Context, id, username string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET username=$2, updated_at=NOW() WHERE id=$1`, id, username)
	return err
}

func (s *Service) updateEmail(ctx context.Context, id, email string) error {
	if s.pg == nil {
		return nil
	}
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return fmt.Errorf("email required")
	}
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return err
	}

	if u == nil {
		return fmt.Errorf("user not found")
	}

	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		return nil
	}

	if _, err := s.pg.Exec(ctx, `UPDATE profiles.users SET email=lower($2), email_verified=false, updated_at=NOW() WHERE id=$1`, id, trimmed); err != nil {
		return err
	}

	_ = s.RequestEmailVerification(ctx, trimmed, 0)
	return nil
}

// RequestEmailChange initiates an email change by sending a verification code to the new email.
// The current email is NOT changed until the user confirms via ConfirmEmailChange.
// Also sends a notification to the old email for security.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	trimmed := strings.TrimSpace(newEmail)
	if trimmed == "" {
		return fmt.Errorf("email required")
	}

	// Get user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	// Check if trying to change to the same email
	if u.Email != nil && strings.EqualFold(*u.Email, trimmed) {
		return fmt.Errorf("new email is the same as current email")
	}

	// Check if new email is already in use by another user
	existing, _ := s.getUserByEmail(ctx, trimmed)
	if existing != nil && existing.ID != userID {
		return fmt.Errorf("email already in use")
	}

	// Previous pending email verification is overwritten by storeEmailVerification.

	// Generate 6-character alphanumeric code (A-Z, 0-9)
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	// TTL for email change is 24 hours (longer than regular verification)
	ttl := 24 * time.Hour
	exp := time.Now().Add(ttl)

	// Create verification token with the NEW email address
	if err := s.createEmailVerifyToken(ctx, userID, hash, trimmed, exp); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send verification code to NEW email
	if s.email != nil {
		_ = s.email.SendEmailVerificationCode(ctx, trimmed, username, code)
	} else {
		stdlog.Printf("[authkit/dev-email] email change verify to=%s username=%s code=%s", trimmed, username, code)
	}

	// Send notification to OLD email about the change request
	if u.Email != nil && s.email != nil {
		// Note: SendEmailVerificationCode is not ideal for notifications, but it's what we have
		// In production, you'd want a dedicated SendEmailChangeNotification method
		stdlog.Printf("[authkit/security] Email change requested for user %s from %s to %s", userID, *u.Email, trimmed)
	}

	return nil
}

// ConfirmEmailChange verifies the code and updates the user's email address.
// This is called when the user enters the verification code sent to their new email.
func (s *Service) ConfirmEmailChange(ctx context.Context, userID, code string) error {
	if s.pg == nil {
		return jwt.ErrTokenUnverifiable
	}

	// Verify and consume the token
	rec, err := s.useEmailVerifyToken(ctx, sha256Hex(code))
	if err != nil {
		return err
	}

	// Ensure token belongs to this user
	if rec.UserID != userID {
		return jwt.ErrTokenInvalidClaims
	}

	// The email in the token is the NEW email they want to change to
	if rec.Email == nil {
		return fmt.Errorf("invalid verification token")
	}

	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil || u == nil {
		return errOrUnauthorized(err)
	}

	// Check if the email in the token is different from current email (it's an email change)
	if u.Email != nil && strings.EqualFold(*u.Email, *rec.Email) {
		// Same email - just verify it
		return s.setEmailVerified(ctx, userID, true)
	}

	// Different email - this is an email change request
	// Update the email and mark as verified
	_, err = s.pg.Exec(ctx, `UPDATE profiles.users SET email=lower($2), email_verified=true, updated_at=NOW() WHERE id=$1`, userID, *rec.Email)
	if err != nil {
		return err
	}

	return nil
}

// ResendEmailChangeCode resends the verification code for a pending email change.
func (s *Service) ResendEmailChangeCode(ctx context.Context, userID string) error {
	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user not found")
	}

	var pendingEmail string
	if s.useEphemeralStore() {
		rec, err := s.getEmailVerificationByUser(ctx, userID)
		if err != nil || rec == nil || rec.Email == nil {
			return fmt.Errorf("no pending email change found")
		}
		pendingEmail = *rec.Email
	} else {
		return fmt.Errorf("no pending email change found")
	}

	// Check if pending email is different from current (it's a change request, not just verification)
	if u.Email != nil && strings.EqualFold(*u.Email, pendingEmail) {
		return fmt.Errorf("no pending email change found")
	}

	// Previous pending email verification is overwritten by storeEmailVerification.

	// Generate new code
	code := randAlphanumeric(6)
	hash := sha256Hex(code)
	ttl := 24 * time.Hour
	exp := time.Now().Add(ttl)

	// Create new verification token
	if err := s.createEmailVerifyToken(ctx, userID, hash, pendingEmail, exp); err != nil {
		return err
	}

	username := ""
	if u.Username != nil {
		username = *u.Username
	}

	// Send new code
	if s.email != nil {
		_ = s.email.SendEmailVerificationCode(ctx, pendingEmail, username, code)
	} else {
		stdlog.Printf("[authkit/dev-email] email change resend to=%s username=%s code=%s", pendingEmail, username, code)
	}

	return nil
}

// GetPendingEmailChange retrieves the pending email change for a user, if any.
func (s *Service) GetPendingEmailChange(ctx context.Context, userID string) (string, error) {
	// Get current user
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", fmt.Errorf("user not found")
	}

	// Check if there's a pending email verification
	var pendingEmail string
	if s.useEphemeralStore() {
		rec, err := s.getEmailVerificationByUser(ctx, userID)
		if err != nil || rec == nil || rec.Email == nil {
			return "", nil
		}
		pendingEmail = *rec.Email
	} else {
		return "", nil
	}

	// Check if it's different from current email (it's a change request)
	if u.Email != nil && strings.EqualFold(*u.Email, pendingEmail) {
		return "", nil // Just a verification, not a change
	}

	return pendingEmail, nil
}

func (s *Service) updateBiography(ctx context.Context, id string, bio *string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET biography=$2, updated_at=NOW() WHERE id=$1`, id, bio)
	return err
}

// setPasswordSet removed; presence of password is inferred from profiles.user_passwords

func (s *Service) getPasswordHash(ctx context.Context, userID string) (hash, algo string, params []byte, err error) {
	if s.pg == nil {
		return "", "", nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT password_hash, hash_algo, COALESCE(hash_params,'{}'::jsonb) FROM profiles.user_passwords WHERE user_id=$1`, userID)
	err = row.Scan(&hash, &algo, &params)
	return
}

func (s *Service) upsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `INSERT INTO profiles.user_passwords (user_id, password_hash, hash_algo, hash_params)
VALUES ($1,$2,$3,$4)
ON CONFLICT (user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash, hash_algo=EXCLUDED.hash_algo, hash_params=EXCLUDED.hash_params, password_updated_at=NOW()`, userID, hash, algo, params)
	return err
}

// email verification tokens
type emailVerifyToken struct {
	UserID string
	Email  *string
}

func (s *Service) createEmailVerifyToken(ctx context.Context, userID, tokenHash string, email string, exp time.Time) error {
	if !s.useEphemeralStore() {
		return fmt.Errorf("ephemeral store not configured")
	}
	var em *string
	if strings.TrimSpace(email) != "" {
		v := normalizeEmail(email)
		em = &v
	}
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return s.storeEmailVerification(ctx, userID, tokenHash, em, ttl)
}

func (s *Service) useEmailVerifyToken(ctx context.Context, tokenHash string) (*emailVerifyToken, error) {
	if s.useEphemeralStore() {
		return s.consumeEmailVerification(ctx, tokenHash)
	}
	return nil, jwt.ErrTokenUnverifiable
}

func (s *Service) useResetToken(ctx context.Context, tokenHash string) (struct{ UserID string }, error) {
	if s.useEphemeralStore() {
		userID, err := s.consumePasswordReset(ctx, tokenHash)
		return struct{ UserID string }{UserID: userID}, err
	}
	return struct{ UserID string }{}, jwt.ErrTokenUnverifiable
}

func (s *Service) createResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	if s.useEphemeralStore() {
		ttl := time.Until(expiresAt)
		if ttl <= 0 {
			ttl = time.Hour
		}
		return s.storePasswordReset(ctx, tokenHash, userID, ttl)
	}
	return fmt.Errorf("ephemeral store not configured")
}

func (s *Service) listRoleSlugsByUser(ctx context.Context, userID string) []string {
	if s.pg == nil {
		return nil
	}
	rows, err := s.pg.Query(ctx, `SELECT r.slug FROM profiles.user_roles ur JOIN profiles.roles r ON ur.role_id=r.id WHERE ur.user_id=$1 AND r.deleted_at IS NULL`, userID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var slug string
		if rows.Scan(&slug) == nil {
			out = append(out, slug)
		}
	}
	return out
}

func (s *Service) assignRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	var roleID string
	if err := s.pg.QueryRow(ctx, `SELECT id FROM profiles.roles WHERE slug=$1`, slug).Scan(&roleID); err != nil {
		return err
	}
	_, err := s.pg.Exec(ctx, `INSERT INTO profiles.user_roles (user_id, role_id) VALUES ($1,$2) ON CONFLICT (user_id, role_id) DO NOTHING`, userID, roleID)
	return err
}

func (s *Service) removeRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `DELETE FROM profiles.user_roles ur USING profiles.roles r WHERE ur.role_id=r.id AND ur.user_id=$1 AND r.slug=$2`, userID, slug)
	return err
}

// Exported wrappers for admin endpoints
func (s *Service) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.assignRoleBySlug(ctx, userID, slug)
}
func (s *Service) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.removeRoleBySlug(ctx, userID, slug)
}

// Public helpers for HTTP adapters
func (s *Service) ListRoleSlugsByUser(ctx context.Context, userID string) []string {
	return s.listRoleSlugsByUser(ctx, userID)
}
func (s *Service) GetEmailByUserID(ctx context.Context, id string) (string, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil || u == nil {
		return "", err
	}
	if u.Email == nil {
		return "", nil
	}
	return *u.Email, nil
}
func (s *Service) UpdateUsername(ctx context.Context, id, username string) error {
	return s.updateUsername(ctx, id, username)
}
func (s *Service) UpdateEmail(ctx context.Context, id, email string) error {
	return s.updateEmail(ctx, id, email)
}
func (s *Service) SetActive(ctx context.Context, id string, active bool) error {
	return s.setActive(ctx, id, active)
}
func (s *Service) UpdateBiography(ctx context.Context, id string, bio *string) error {
	return s.updateBiography(ctx, id, bio)
}

// Admin listing/get/delete
type AdminUser struct {
	ID              string     `json:"id"`
	Email           *string    `json:"email"` // Nullable for phone-only users
	PhoneNumber     *string    `json:"phone_number"`
	Username        *string    `json:"username"`
	DiscordUsername *string    `json:"discord_username"`
	EmailVerified   bool       `json:"email_verified"`
	PhoneVerified   bool       `json:"phone_verified"`
	IsActive        bool       `json:"is_active"`
	Biography       *string    `json:"biography"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLogin       *time.Time `json:"last_login"`
	Roles           []string   `json:"roles"`
	Entitlements    []string   `json:"entitlements"`
}

// AdminListUsersResult contains paginated user list with total count
type AdminListUsersResult struct {
	Users  []AdminUser `json:"users"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

func (s *Service) AdminListUsers(ctx context.Context, page, pageSize int, filter, search string) (*AdminListUsersResult, error) {
	if s.pg == nil {
		return &AdminListUsersResult{Users: []AdminUser{}, Total: 0, Limit: pageSize, Offset: 0}, nil
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	offset := (page - 1) * pageSize

	// Only support these filters:
	// "All users", "Super administrators", "Taggers", "Bloggers"

	where := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1
	from := "profiles.users u"
	orderBy := "u.created_at DESC"
	limitOverride := 0

	switch filter {
	case "super administrators":
		from += " JOIN profiles.user_roles ur ON ur.user_id = u.id JOIN profiles.roles r ON ur.role_id = r.id AND r.deleted_at IS NULL"
		where = append(where, "r.slug = $"+fmt.Sprint(argIdx))
		args = append(args, "admin")
		argIdx++
	case "taggers":
		from += " JOIN profiles.user_roles ur ON ur.user_id = u.id JOIN profiles.roles r ON ur.role_id = r.id AND r.deleted_at IS NULL"
		where = append(where, "r.slug = $"+fmt.Sprint(argIdx))
		args = append(args, "tagger")
		argIdx++
	case "bloggers":
		from += " JOIN profiles.user_roles ur ON ur.user_id = u.id JOIN profiles.roles r ON ur.role_id = r.id AND r.deleted_at IS NULL"
		where = append(where, "r.slug = $"+fmt.Sprint(argIdx))
		args = append(args, "blogger")
		argIdx++
	case "10 random premium members":
		// Use a subquery to select 10 random premium user IDs, then join back to users for full data
		from = "profiles.users u JOIN (SELECT u.id FROM profiles.users u JOIN profiles.user_roles ur ON ur.user_id = u.id JOIN profiles.roles r ON ur.role_id = r.id AND r.deleted_at IS NULL WHERE r.slug = $" + fmt.Sprint(argIdx) + " ORDER BY RANDOM() LIMIT 10) sub ON u.id = sub.id"
		args = append(args, "premium")
		argIdx++
		// No additional where clause needed
		orderBy = "u.created_at DESC"
		limitOverride = 0
	}

	// Search (username, email, phone)
	if search != "" {
		where = append(where, "(u.username ILIKE $"+fmt.Sprint(argIdx)+" OR u.email ILIKE $"+fmt.Sprint(argIdx)+" OR u.phone_number ILIKE $"+fmt.Sprint(argIdx)+")")
		args = append(args, "%"+search+"%")
		argIdx++
	}

	countQuery := "SELECT COUNT(DISTINCT u.id) FROM " + from + " WHERE " + strings.Join(where, " AND ")
	var total int64
	if err := s.pg.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	selectCols := "u.id::text, u.email, u.phone_number, u.username, u.discord_username, u.email_verified, u.phone_verified, u.is_active, u.biography, u.created_at, u.updated_at, u.last_login"
	query := "SELECT DISTINCT " + selectCols + " FROM " + from + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + orderBy
	if limitOverride > 0 {
		query += " LIMIT " + fmt.Sprint(limitOverride)
	} else {
		query += " OFFSET $" + fmt.Sprint(argIdx) + " LIMIT $" + fmt.Sprint(argIdx+1)
		args = append(args, offset, pageSize)
	}

	rows, err := s.pg.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminUser
	for rows.Next() {
		var a AdminUser
		if err := rows.Scan(&a.ID, &a.Email, &a.PhoneNumber, &a.Username, &a.DiscordUsername, &a.EmailVerified, &a.PhoneVerified, &a.IsActive, &a.Biography, &a.CreatedAt, &a.UpdatedAt, &a.LastLogin); err != nil {
			return nil, err
		}
		a.Roles = s.listRoleSlugsByUser(ctx, a.ID)
		a.Entitlements = s.ListEntitlements(ctx, a.ID)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &AdminListUsersResult{Users: out, Total: total, Limit: pageSize, Offset: offset}, nil
}

func (s *Service) AdminGetUser(ctx context.Context, id string) (*AdminUser, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	a := &AdminUser{
		ID: u.ID, Email: u.Email, PhoneNumber: u.PhoneNumber, Username: u.Username, DiscordUsername: u.DiscordUsername,
		EmailVerified: u.EmailVerified, PhoneVerified: u.PhoneVerified, IsActive: u.IsActive,
		Biography: u.Biography, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, LastLogin: u.LastLogin,
	}
	a.Roles = s.listRoleSlugsByUser(ctx, id)
	a.Entitlements = s.ListEntitlements(ctx, id)
	return a, nil
}

func (s *Service) AdminDeleteUser(ctx context.Context, id string) error {
	if s.pg == nil {
		return nil
	}
	// Revoke all sessions
	_, _ = s.pg.Exec(ctx, `UPDATE profiles.refresh_sessions SET revoked_at=now() WHERE user_id=$1 AND issuer=$2`, id, s.opts.Issuer)
	// Delete user
	_, err := s.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, id)
	return err
}

// Additional public helpers used by OIDC flow
func (s *Service) GetProviderLink(ctx context.Context, provider, subject string) (string, *string, error) {
	return s.getProviderLink(ctx, provider, subject)
}
func (s *Service) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.getUserByEmail(ctx, email)
}
func (s *Service) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.getUserByUsername(ctx, username)
}
func (s *Service) CreateUser(ctx context.Context, email, username string) (*User, error) {
	return s.createUser(ctx, email, username)
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
func (s *Service) SetEmailVerified(ctx context.Context, id string, v bool) error {
	return s.setEmailVerified(ctx, id, v)
}
func (s *Service) UpsertPasswordHash(ctx context.Context, userID, hash, algo string, params []byte) error {
	return s.upsertPasswordHash(ctx, userID, hash, algo, params)
}
func (s *Service) DeriveUsername(email string) string { return deriveUsername(email) }

// Sign-in history
// LogLogin records a login event via the configured AuthEventLogger (best-effort).
// method examples: "password_login", "oidc_login" (optionally suffixed with provider slug by the caller if desired).
func (s *Service) LogLogin(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	_ = s.authlog.LogLogin(ctx, userID, s.opts.Issuer, method, sessionID, ip, ua)
}

// Deprecated: LogSignin kept for compatibility. Use LogLogin with a session ID.
func (s *Service) LogSignin(ctx context.Context, userID string, action string, ip *string, ua *string) {
	if s.authlog == nil {
		return
	}
	_ = s.authlog.LogLogin(ctx, userID, s.opts.Issuer, action, "", ip, ua)
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
	_ = s.email.SendWelcome(ctx, *u.Email, username)
}

type SigninEntry struct {
	OccurredAt time.Time
	IPAddr     *string
	UserAgent  *string
	Action     string
}

func (s *Service) AdminGetUserSignins(ctx context.Context, userID string, page, pageSize int) ([]SigninEntry, error) {
	// Sign-in history moved to ClickHouse; this endpoint no longer sources from Postgres.
	// Returning empty data keeps admin UI functional without Postgres signins.
	return []SigninEntry{}, nil
}

// Provider link management
func (s *Service) countProviderLinks(ctx context.Context, userID string) int {
	if s.pg == nil {
		return 0
	}
	var n int
	_ = s.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.user_providers WHERE user_id=$1`, userID).Scan(&n)
	return n
}
func (s *Service) hasPassword(ctx context.Context, userID string) bool {
	if s.pg == nil {
		return false
	}
	var exists bool
	_ = s.pg.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM profiles.user_passwords WHERE user_id=$1)`, userID).Scan(&exists)
	return exists
}
func (s *Service) unlinkProvider(ctx context.Context, userID, provider string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `DELETE FROM profiles.user_providers WHERE user_id=$1 AND provider_slug=$2`, userID, provider)
	return err
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

// Issuer-based provider link helpers (preferred)
func (s *Service) GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error) {
	return s.getProviderLink(ctx, issuer, subject)
}
func (s *Service) LinkProviderByIssuer(ctx context.Context, userID, issuer, providerSlug, subject string, email *string) error {
	// Store provider slug for UI, enforce uniqueness on (issuer, subject) and (user_id, issuer)
	// Remove any existing provider link for this user+issuer with different subject (allows switching Discord accounts)
	if s.pg == nil {
		return nil
	}
	// First delete old Discord link if user is switching to a different Discord account
	_, _ = s.pg.Exec(ctx, `DELETE FROM profiles.user_providers WHERE user_id=$1 AND issuer=$2 AND subject != $3`, userID, issuer, subject)
	// Then insert/update the new link
	_, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.user_providers (user_id, issuer, provider_slug, subject, email_at_provider)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (issuer, subject) DO UPDATE
		SET email_at_provider=EXCLUDED.email_at_provider,
		    provider_slug=COALESCE(EXCLUDED.provider_slug, profiles.user_providers.provider_slug)
	`, userID, issuer, providerSlug, subject, email)
	return err
}

// ListEntitlements returns current entitlements for a user (fresh from provider).
func (s *Service) ListEntitlements(ctx context.Context, userID string) []string {
	if s.entitlements == nil {
		return nil
	}
	details, err := s.entitlements.ListEntitlements(ctx, userID)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(details))
	for _, d := range details {
		out = append(out, d.Name)
	}
	return out
}

// ListEntitlementsDetailed returns detailed entitlements (name + metadata).
func (s *Service) ListEntitlementsDetailed(ctx context.Context, userID string) []entpg.Entitlement {
	if s.entitlements == nil {
		return nil
	}
	details, err := s.entitlements.ListEntitlements(ctx, userID)
	if err != nil {
		return nil
	}
	return details
}

func (s *Service) getProviderLink(ctx context.Context, issuer, subject string) (userID string, email *string, err error) {
	if s.pg == nil {
		return "", nil, nil
	}
	row := s.pg.QueryRow(ctx, `SELECT user_id, email_at_provider FROM profiles.user_providers WHERE issuer=$1 AND subject=$2`, issuer, subject)
	var uid string
	var e *string
	if err := row.Scan(&uid, &e); err != nil {
		return "", nil, err
	}
	return uid, e, nil
}

func (s *Service) linkProvider(ctx context.Context, userID, issuer, subject string, email *string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `INSERT INTO profiles.user_providers (user_id, issuer, subject, email_at_provider)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (issuer, subject) DO UPDATE SET email_at_provider=EXCLUDED.email_at_provider`, userID, issuer, subject, email)
	return err
}

// setProviderUsername stores a provider-specific username into profile jsonb as {"username": <value>}.
func (s *Service) setProviderUsername(ctx context.Context, userID, issuer, subject, username string) error {
	if s.pg == nil {
		return nil
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.user_providers SET profile = jsonb_build_object('username', $4)
        WHERE user_id=$1 AND issuer=$2 AND subject=$3`, userID, issuer, subject, username)
	return err
}

// getProviderUsername fetches provider profile->>'username' for the given user (first match by provider).
func (s *Service) getProviderUsername(ctx context.Context, userID, provider string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	var uname *string
	err := s.pg.QueryRow(ctx, `SELECT profile->>'username' FROM profiles.user_providers WHERE user_id=$1 AND provider_slug=$2 ORDER BY created_at DESC LIMIT 1`, userID, provider).Scan(&uname)
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
		clean = []rune{'u', 's', 'r'}
	}
	if clean[0] < 'a' || clean[0] > 'z' {
		clean = append([]rune{'u'}, clean...)
	}
	if len(clean) > 32 {
		clean = clean[:32]
	}
	return string(clean)
}

// getDiscordUsername retrieves the discord username for a user, preferring the
// dedicated column on profiles.users and falling back to user_providers.profile JSON.
func (s *Service) getDiscordUsername(ctx context.Context, userID string) (string, error) {
	if s.pg == nil {
		return "", nil
	}
	// Prefer stored column
	var uname *string
	if err := s.pg.QueryRow(ctx, `SELECT discord_username FROM profiles.users WHERE id=$1`, userID).Scan(&uname); err == nil {
		if uname != nil {
			return *uname, nil
		}
	}
	// Fallback to provider profile JSON
	return s.getProviderUsername(ctx, userID, "discord")
}

// (legacy ChangePassword removed in favor of unified ChangePassword with session revocation)

// --- Pending Registration Helpers ---

// PendingRegistration represents an unverified registration
type PendingRegistration struct {
	Email        string
	Username     string
	PasswordHash string
}

// GetPendingRegistrationByEmail looks up a pending registration by email.
func (s *Service) GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error) {
	if s.useEphemeralStore() {
		token, ok, err := s.ephemGetString(ctx, keyPendingRegEmail+normalizeEmail(email))
		if err != nil || !ok || token == "" {
			return nil, err
		}
		data, ok, err := s.loadPendingRegistration(ctx, token)
		if err != nil || !ok {
			return nil, err
		}
		return &PendingRegistration{
			Email:        data.Email,
			Username:     data.Username,
			PasswordHash: data.PasswordHash,
		}, nil
	}
	return nil, nil
}

// GetPendingPhoneRegistrationByPhone looks up a pending phone registration by phone number.
func (s *Service) GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error) {
	if s.useEphemeralStore() {
		token, ok, err := s.ephemGetString(ctx, keyPendingPhonePhone+phone)
		if err != nil || !ok || token == "" {
			return nil, err
		}
		data, ok, err := s.loadPendingPhoneRegistration(ctx, token)
		if err != nil || !ok {
			return nil, err
		}
		return &PendingRegistration{
			Email:        "",
			Username:     data.Username,
			PasswordHash: data.PasswordHash,
		}, nil
	}
	return nil, nil
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

// --- Two-Factor Authentication (2FA) ---

// TwoFactorSettings represents a user's 2FA configuration
type TwoFactorSettings struct {
	UserID      string
	Enabled     bool
	Method      string // "email" or "sms"
	PhoneNumber *string
	BackupCodes []string // Hashed backup codes
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Enable2FA enables two-factor authentication for a user and generates backup codes.
// Returns the plaintext backup codes (caller must show these to user ONCE).
func (s *Service) Enable2FA(ctx context.Context, userID, method string, phoneNumber *string) ([]string, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	// Validate method
	if method != "email" && method != "sms" {
		return nil, fmt.Errorf("invalid 2FA method: must be 'email' or 'sms'")
	}

	// If SMS, phone number is required
	if method == "sms" && (phoneNumber == nil || *phoneNumber == "") {
		return nil, fmt.Errorf("phone number required for SMS 2FA")
	}

	// Generate 10 backup codes (8-character alphanumeric)
	plaintextCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := randAlphanumericUppercase(8) // Generate 8-char code
		plaintextCodes[i] = code
		hashedCodes[i] = sha256Hex(code)
	}

	// Insert or update 2FA settings
	_, err := s.pg.Exec(ctx, `
		INSERT INTO profiles.two_factor_settings (user_id, enabled, method, phone_number, backup_codes, updated_at)
		VALUES ($1, true, $2, $3, $4, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			enabled = true,
			method = $2,
			phone_number = $3,
			backup_codes = $4,
			updated_at = NOW()
	`, userID, method, phoneNumber, hashedCodes)
	if err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

// Disable2FA disables two-factor authentication for a user
func (s *Service) Disable2FA(ctx context.Context, userID string) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}

	_, err := s.pg.Exec(ctx, `
		UPDATE profiles.two_factor_settings
		SET enabled = false, updated_at = NOW()
		WHERE user_id = $1
	`, userID)
	return err
}

// Get2FASettings retrieves a user's 2FA settings
func (s *Service) Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error) {
	if s.pg == nil {
		return nil, fmt.Errorf("postgres not configured")
	}

	row := s.pg.QueryRow(ctx, `
		SELECT user_id, enabled, method, phone_number, backup_codes, created_at, updated_at
		FROM profiles.two_factor_settings
		WHERE user_id = $1
	`, userID)

	var settings TwoFactorSettings
	var backupCodes []string
	err := row.Scan(&settings.UserID, &settings.Enabled, &settings.Method, &settings.PhoneNumber, &backupCodes, &settings.CreatedAt, &settings.UpdatedAt)
	if err != nil {
		return nil, err
	}
	settings.BackupCodes = backupCodes

	return &settings, nil
}

// Require2FAForLogin sends a 2FA code to the user's configured method.
// Returns the destination (email/phone) where the code was sent.
// This should be called after successful password verification.
func (s *Service) Require2FAForLogin(ctx context.Context, userID string) (string, error) {
	// Get user's 2FA settings
	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("2FA not enabled")
	}
	if !settings.Enabled {
		return "", fmt.Errorf("2FA not enabled")
	}

	// Get user info for email/username
	user, err := s.AdminGetUser(ctx, userID)
	if err != nil {
		return "", err
	}

	// Generate 6-digit numeric code
	code := randAlphanumeric(6)
	hash := sha256Hex(code)

	// Determine destination
	var destination string
	if settings.Method == "email" {
		if user.Email == nil {
			return "", fmt.Errorf("no email address configured")
		}
		destination = *user.Email
	} else { // sms
		if settings.PhoneNumber == nil {
			return "", fmt.Errorf("no phone number configured for SMS 2FA")
		}
		destination = *settings.PhoneNumber
	}

	exp := time.Now().Add(10 * time.Minute) // 10 minute expiration for 2FA codes
	if s.useEphemeralStore() {
		if err := s.storeTwoFactorCode(ctx, userID, hash, settings.Method, destination, time.Until(exp)); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("ephemeral store not configured")
	}

	// Send the code
	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	if settings.Method == "email" {
		if s.email != nil {
			_ = s.email.SendLoginCode(ctx, destination, username, code)
		} else {
			// In production, require email to be configured for email 2FA
			if !isDevEnvironment(getEnvironment()) {
				return "", fmt.Errorf("Email 2FA unavailable: email sender not configured (email 2FA requires email in production)")
			}
			// Dev mode: log code to stdout
			stdlog.Printf("[authkit/dev-2fa] email 2FA code for %s: %s", destination, code)
		}
	} else { // sms
		if s.sms != nil {
			_ = s.sms.SendLoginCode(ctx, destination, code)
		} else {
			// In production, require SMS to be configured for SMS 2FA
			if !isDevEnvironment(getEnvironment()) {
				return "", fmt.Errorf("SMS 2FA unavailable: Twilio not configured (SMS 2FA requires Twilio in production)")
			}
			// Dev mode: log code to stdout
			stdlog.Printf("[authkit/dev-2fa] SMS 2FA code for %s: %s", destination, code)
		}
	}

	return destination, nil
}

// Verify2FACode verifies a 2FA code entered by the user during login.
// Returns true if code is valid, false otherwise.
func (s *Service) Verify2FACode(ctx context.Context, userID, code string) (bool, error) {
	hash := sha256Hex(code)

	if s.useEphemeralStore() {
		return s.consumeTwoFactorCode(ctx, userID, hash)
	}
	return false, fmt.Errorf("ephemeral store not configured")
}

// VerifyBackupCode verifies a 2FA backup code for account recovery.
// On success, removes the used backup code from the user's backup codes.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error) {
	if s.pg == nil {
		return false, fmt.Errorf("postgres not configured")
	}

	settings, err := s.Get2FASettings(ctx, userID)
	if err != nil || !settings.Enabled {
		return false, fmt.Errorf("2FA not enabled")
	}

	hash := sha256Hex(backupCode)

	// Check if backup code exists
	found := false
	for _, hashedCode := range settings.BackupCodes {
		if hashedCode == hash {
			found = true
			break
		}
	}

	if !found {
		return false, nil
	}

	// Remove the used backup code
	newCodes := make([]string, 0, len(settings.BackupCodes)-1)
	for _, hashedCode := range settings.BackupCodes {
		if hashedCode != hash {
			newCodes = append(newCodes, hashedCode)
		}
	}

	_, err = s.pg.Exec(ctx, `
		UPDATE profiles.two_factor_settings
		SET backup_codes = $1, updated_at = NOW()
		WHERE user_id = $2
	`, newCodes, userID)
	if err != nil {
		return false, err
	}

	return true, nil
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

	_, err = s.pg.Exec(ctx, `
		UPDATE profiles.two_factor_settings
		SET backup_codes = $1, updated_at = NOW()
		WHERE user_id = $2
	`, hashedCodes, userID)
	if err != nil {
		return nil, err
	}

	return plaintextCodes, nil
}

// randAlphanumericUppercase generates a random uppercase alphanumeric string (A-Z, 0-9)
// Used for backup codes which are longer and case-sensitive
func randAlphanumericUppercase(n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude ambiguous chars
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = chars[randInt(len(chars))]
	}
	return string(b)
}

// getEnvironment reads the environment from ENV, APP_ENV, or ENVIRONMENT variables
func getEnvironment() string {
	env := os.Getenv("ENV")
	if env == "" {
		env = os.Getenv("APP_ENV")
	}
	if env == "" {
		env = os.Getenv("ENVIRONMENT")
	}
	return env
}

// isDevEnvironment returns true unless the environment is explicitly set to prod/production
func isDevEnvironment(env string) bool {
	e := strings.ToLower(strings.TrimSpace(env))
	// Only production environments are considered non-dev
	if e == "prod" || e == "production" {
		return false
	}
	// Everything else (dev, development, local, staging, empty, etc.) is considered dev
	return true
}

// SetUserActive sets the is_active property for a user.
func (s *Service) SetUserActive(ctx context.Context, userID string, isActive bool) error {
	if s.pg == nil {
		return fmt.Errorf("postgres not configured")
	}
	_, err := s.pg.Exec(ctx, `UPDATE profiles.users SET is_active=$2, updated_at=NOW() WHERE id=$1`, userID, isActive)
	return err
}
