package authkit

import "time"

// User is the public user view returned by AuthKit lookups. Plain data — part of
// the wire contract shared by the embedded engine and (Phase 2) the remote SDK.
// See #138 (contract inversion): definitions live here in the lean, pgx-free
// contract package; internal/authcore aliases back to these.
type User struct {
	ID              string
	Email           *string // Nullable - phone-only users have NULL email
	PhoneNumber     *string
	Username        *string
	DiscordUsername *string
	EmailVerified   bool
	PhoneVerified   bool
	BannedAt        *time.Time
	BannedUntil     *time.Time
	BanReason       *string
	BannedBy        *string
	DeletedAt       *time.Time
	Biography       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastLogin       *time.Time
}

// Session is a sanitized session view (no tokens). Part of the wire contract.
type Session struct {
	ID                  string
	FamilyID            string
	CreatedAt           time.Time
	LastAuthenticatedAt *time.Time
	LastUsedAt          time.Time
	ExpiresAt           *time.Time
	RevokedAt           *time.Time
	UserAgent           *string
	IPAddr              *string
}
