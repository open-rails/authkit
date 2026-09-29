package iam

import (
	"strings"
	"time"
)

// User is an account. It is the privileged view: it carries contact details,
// so render other people with PublicUser.
type User struct {
	ID                string     `json:"id"`
	Email             string     `json:"email,omitempty"`
	Phone             string     `json:"phone,omitempty"`
	Username          string     `json:"username,omitempty"`
	EmailVerified     bool       `json:"email_verified"`
	PhoneVerified     bool       `json:"phone_verified"`
	PreferredLanguage string     `json:"preferred_language,omitempty"`
	AvatarURL         string     `json:"avatar_url,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	LastLogin         *time.Time `json:"last_login,omitempty"`
	DeletedAt         *time.Time `json:"deleted_at,omitempty"`
	// Ban is nil when no ban is in force.
	Ban *BanState `json:"ban,omitempty"`
}

// BanState is a ban in force. By is "" when the system or a machine banned.
type BanState struct {
	At     time.Time  `json:"at"`
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason,omitempty"`
	By     string     `json:"by,omitempty"`
}

// PublicUser is what other people may see of an account. A deleted account
// is a tombstone: Deleted is set and every other field except ID is zero.
type PublicUser struct {
	ID        string    `json:"id"`
	Username  string    `json:"username,omitempty"`
	AvatarURL string    `json:"avatar_url,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Deleted   bool      `json:"deleted,omitempty"`
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

// ReadOption adjusts a read.
type ReadOption struct{ includeDeleted bool }

// IncludeDeleted makes a read return soft-deleted accounts too.
func IncludeDeleted() ReadOption { return ReadOption{includeDeleted: true} }

// IncludesDeleted reports whether opts ask for deleted accounts.
func IncludesDeleted(opts []ReadOption) bool {
	for _, o := range opts {
		if o.includeDeleted {
			return true
		}
	}
	return false
}

// NewUser creates a native account. Verified flags are the system's
// assertion that the address was proven elsewhere.
type NewUser struct {
	Email, Phone, Username, Password string
	EmailVerified, PhoneVerified     bool
}

// UserUpdate changes an account; nil fields stay unchanged, and "" clears
// AvatarURL and PreferredLanguage. A new Email or Phone starts unverified
// unless the same update sets its verified flag.
type UserUpdate struct {
	Email, Phone, Username, AvatarURL, PreferredLanguage, Password *string
	EmailVerified, PhoneVerified                                   *bool
	PasswordHash                                                   *PasswordHash
}

// PasswordHash is an imported password hash: Algo is argon2id or bcrypt,
// validated at write.
type PasswordHash struct{ Hash, Algo string }

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
	UserStatusActive  UserStatus = "active"  // not deleted, not banned
	UserStatusBanned  UserStatus = "banned"  // not deleted, banned
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

// UserQuery lists accounts. Search matches username, email and phone;
// RootRole filters on a role in the root group; Entitlement needs an
// entitlements provider that can list subjects.
type UserQuery struct {
	Search      string
	Status      UserStatus
	RootRole    Role
	Entitlement string
	Sort        UserSort
	Desc        bool
	Page        PageRequest
}

// Session is one refresh session on this deployment's issuer.
type Session struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt time.Time  `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	IP         string     `json:"ip,omitempty"`
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
	SessionID  string           `json:"session_id,omitempty"`
	Method     string           `json:"method,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	IP         string           `json:"ip,omitempty"`
	UserAgent  string           `json:"user_agent,omitempty"`
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

// AccessTokenOptions shapes a host-minted access token. Claims AuthKit
// reserves are dropped.
type AccessTokenOptions struct {
	SessionID string
	TTL       time.Duration // 0 = the configured access-token lifetime
	Claims    map[string]any
}
