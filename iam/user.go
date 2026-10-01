package iam

import (
	"crypto/ed25519"
	"strings"
	"time"
)

// User is an account. It is the privileged view: it carries contact details,
// so render other people with PublicUser. A nil field is unset.
type User struct {
	ID                string     `json:"id"`
	Email             *string    `json:"email"`
	Phone             *string    `json:"phone_number"`
	Username          string     `json:"username"`
	EmailVerified     bool       `json:"email_verified"`
	PhoneVerified     bool       `json:"phone_verified"`
	PreferredLanguage *string    `json:"preferred_language"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastLogin         *time.Time `json:"last_login"`
	DeletedAt         *time.Time `json:"deleted_at"`
	// Ban is nil when no ban is in force.
	Ban *BanState `json:"ban"`
	// PublicMetadata is the account's public metadata (see PublicUser).
	PublicMetadata map[string]any `json:"public_metadata"`
}

// BanState is a ban in force: when it began, until when (nil =
// indefinitely), why, and the account that banned (By, nil for the system or
// a machine).
type BanState struct {
	At     time.Time  `json:"at" yaml:"at"`
	Until  *time.Time `json:"until" yaml:"until"`
	Reason *string    `json:"reason" yaml:"reason"`
	By     *string    `json:"by" yaml:"by"`
}

// PublicUser is what other people may see of an account: never its contacts,
// ban or sign-in data. A deleted account is a tombstone: Deleted is set and
// every other field but ID is empty.
type PublicUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	// CreatedAt is when the account was created: its "member since".
	CreatedAt *time.Time `json:"created_at"`
	Deleted   bool       `json:"deleted"`
	// PublicMetadata is the JSON object only the host writes
	// (Client.PatchPublicMetadata, ImportUsers) and anyone may read: GET /me,
	// GET /users and every PublicUser carry it whole. It is the place for a
	// profile's public fields (an avatar URL, a biography); keep anything
	// private in your own tables, keyed by the account id.
	PublicMetadata map[string]any `json:"public_metadata"`
}

// DisplayName is the username, or "user-<first 8 of id>" for tombstoned and
// unnamed users.
func (u PublicUser) DisplayName() string {
	if !u.Deleted && u.Username != "" {
		return u.Username
	}
	return fallbackDisplayName(u.ID)
}

// PublicDisplayName renders id against a PublicUsers result, including ids the
// batch did not resolve.
func PublicDisplayName(users map[string]PublicUser, id string) string {
	if u, ok := users[id]; ok {
		return u.DisplayName()
	}
	return fallbackDisplayName(id)
}

func fallbackDisplayName(id string) string {
	if len(id) > 8 {
		id = id[:8]
	}
	return "user-" + id
}

// UserKey names how a UserRef addresses an account.
type UserKey string

const (
	UserKeyID       UserKey = "id"
	UserKeyEmail    UserKey = "email"
	UserKeyPhone    UserKey = "phone"
	UserKeyUsername UserKey = "username"
)

// UserRef addresses one account by exactly one key. Build it with UserByID,
// UserByEmail, UserByPhone or UserByUsername; the zero UserRef finds nobody.
type UserRef struct {
	key   UserKey
	value string
}

func UserByID(id string) UserRef       { return UserRef{UserKeyID, strings.TrimSpace(id)} }
func UserByEmail(email string) UserRef { return UserRef{UserKeyEmail, strings.TrimSpace(email)} }
func UserByPhone(phone string) UserRef { return UserRef{UserKeyPhone, strings.TrimSpace(phone)} }
func UserByUsername(username string) UserRef {
	return UserRef{UserKeyUsername, strings.TrimSpace(username)}
}

// Key and Value are the addressing mode and its value.
func (r UserRef) Key() UserKey   { return r.key }
func (r UserRef) Value() string  { return r.value }
func (r UserRef) IsZero() bool   { return r.key == "" || r.value == "" }
func (r UserRef) String() string { return string(r.key) + ":" + r.value }

// NewUser creates a native account. A verified flag asserts that your code
// proved the address; another system's word is not proof (import such
// accounts with ImportUsers).
type NewUser struct {
	Email, Phone, Username, Password string
	EmailVerified, PhoneVerified     bool
}

// UserUpdate changes an account; nil fields stay unchanged, and "" clears
// PreferredLanguage. A new Email or Phone starts unverified unless the same
// update sets its verified flag.
type UserUpdate struct {
	Email, Phone, Username, PreferredLanguage, Password *string
	EmailVerified, PhoneVerified                        *bool
	PasswordHash                                        *PasswordHash
}

// PasswordHash is a password hash made elsewhere (an import, a bootstrap
// manifest, UpdateUser), validated before it is stored.
type PasswordHash struct {
	Hash string   `json:"hash" yaml:"hash"`
	Algo HashAlgo `json:"algo" yaml:"algo"`
}

// HashAlgo names a password hash algorithm.
type HashAlgo string

const (
	HashArgon2id HashAlgo = "argon2id"
	HashBcrypt   HashAlgo = "bcrypt"
	// HashLegacyResetRequired marks a migrated password that can never verify
	// (DES crypt, md5-crypt, a corrupted value). The raw hash is kept for
	// forensics only; the account must reset its password.
	HashLegacyResetRequired HashAlgo = "legacy-reset-required"
)

// Ban bans an account. Until nil bans indefinitely. KeepExisting leaves a ban
// already in force unchanged, so a repeat call is a no-op.
type Ban struct {
	Reason       string
	Until        *time.Time
	KeepExisting bool
}

// UserStatus filters a user list.
type UserStatus string

const (
	UserStatusLive    UserStatus = ""        // not deleted (default)
	UserStatusActive  UserStatus = "active"  // not deleted, no ban in force
	UserStatusBanned  UserStatus = "banned"  // not deleted, a ban in force
	UserStatusDeleted UserStatus = "deleted" // soft-deleted
	UserStatusAny     UserStatus = "any"
)

// UserSort orders a user list; ties break on id.
type UserSort string

const (
	UserSortCreatedAt UserSort = "created_at" // default
	UserSortLastLogin UserSort = "last_login"
	UserSortUsername  UserSort = "username"
	UserSortEmail     UserSort = "email"
)

// UserQuery lists accounts. Search matches text within a username, email or
// phone (at its start, below three characters), an account id, or exactly a
// linked sign-in's subject (a wallet address, a provider's user id), provider
// email or provider username. RootRole filters on a role in the root group;
// Entitlement needs an entitlements provider that can list subjects. Total
// counts every match into ListPage.Total; WithEntitlements fills
// UserEntry.Entitlements from the entitlements provider.
type UserQuery struct {
	Search           string
	Status           UserStatus
	RootRole         Role
	Entitlement      string
	Sort             UserSort
	Desc             bool
	Total            bool
	WithEntitlements bool
	Page             PageRequest
}

// UserEntry is one row of the user directory: the account and its root
// role (nil when it holds none), and, when the query asks, its entitlements.
type UserEntry struct {
	User
	RootRole     *Role    `json:"root_role"`
	Entitlements []string `json:"entitlements"`
}

// DeviceKey is an Ed25519 key a native client signs in with. Current marks
// the key behind the access token of the request that listed it.
type DeviceKey struct {
	ID         string            `json:"id"`
	Label      *string           `json:"label"`
	PublicKey  ed25519.PublicKey `json:"public_key"`
	CreatedAt  time.Time         `json:"created_at"`
	LastUsedAt *time.Time        `json:"last_used_at"`
	RevokedAt  *time.Time        `json:"revoked_at"`
	Current    bool              `json:"current"`
}

// Session is one refresh session on this deployment's issuer. Current marks
// the session behind the access token of the request that listed it.
type Session struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt time.Time  `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	UserAgent  *string    `json:"user_agent"`
	IP         *string    `json:"ip"`
	Current    bool       `json:"current"`
}

// SessionEventKind names an entry of an account's session history.
type SessionEventKind string

const (
	SessionEventCreated          SessionEventKind = "session_created"
	SessionEventFailed           SessionEventKind = "session_failed"
	SessionEventRevoked          SessionEventKind = "session_revoked"
	SessionEventPasswordChange   SessionEventKind = "password_changed"
	SessionEventPasswordRecovery SessionEventKind = "password_recovery"
	// SessionEventAccountSessionsRevoked is one account-wide revocation; each
	// session it ended has its own SessionEventRevoked.
	SessionEventAccountSessionsRevoked SessionEventKind = "account_sessions_revoked"
)

// SessionEvent is one entry of an account's sign-in and session history, kept
// for Config.SessionEventRetention. Method is how a session was created;
// Reason why one was revoked or a sign-in failed.
type SessionEvent struct {
	Kind       SessionEventKind `json:"kind"`
	OccurredAt time.Time        `json:"occurred_at"`
	Issuer     string           `json:"issuer"`
	SessionID  *string          `json:"session_id"`
	Method     *string          `json:"method"`
	Reason     *string          `json:"reason"`
	IP         *string          `json:"ip"`
	UserAgent  *string          `json:"user_agent"`
}

// SessionEventQuery pages an account's session history, newest first. No
// Kinds means every kind.
type SessionEventQuery struct {
	Kinds []SessionEventKind
	Page  PageRequest
}

// AccountSessionRevocation reports an account-wide emergency revocation across
// the configured account issuers (TokenConfig.AccountIssuers). Access tokens
// minted from the revoked sessions and device keys are refused at once by
// every session check (permission checks, Sensitive, account changes); plain
// stateless verification admits them until they expire.
type AccountSessionRevocation struct {
	// Issuers is the exact issuer scope covered, this deployment's first.
	Issuers []string `json:"issuers"`
	// RevokedSessions counts revoked refresh sessions per covered issuer.
	RevokedSessions map[string]int `json:"revoked_sessions"`
	// RevokedDeviceKeys counts revoked device keys; they are not issuer-bound.
	RevokedDeviceKeys int `json:"revoked_device_keys"`
	// UnlistedIssuerSessions counts live sessions left under issuers outside
	// Issuers; nonzero means the account issuer configuration is incomplete.
	UnlistedIssuerSessions int `json:"unlisted_issuer_sessions"`
}

// AccessTokenOptions shapes a host-minted access token. Claims are the host's
// own: one named like an AuthKit claim is refused.
type AccessTokenOptions struct {
	SessionID string
	TTL       time.Duration // 0 = the configured access-token lifetime
	Claims    map[string]any
}
