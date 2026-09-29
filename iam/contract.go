package iam

import "time"

// Shared operation inputs and results, importable without the engine.

// MaxBatch bounds the ids (users, groups, subjects) accepted by one batch call.
const MaxBatch = 500

type AdminUser struct {
	ID              string     `json:"id"`
	Email           *string    `json:"email"` // Nullable for phone-only users
	PhoneNumber     *string    `json:"phone_number"`
	Username        *string    `json:"username"`
	DiscordUsername *string    `json:"discord_username"`
	EmailVerified   bool       `json:"email_verified"`
	PhoneVerified   bool       `json:"phone_verified"`
	BannedAt        *time.Time `json:"banned_at,omitempty"`
	BannedUntil     *time.Time `json:"banned_until,omitempty"`
	BanReason       *string    `json:"ban_reason,omitempty"`
	BannedBy        *string    `json:"banned_by,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	LastLogin       *time.Time `json:"last_login"`
	Roles           []string   `json:"roles"`
	RemovedRoles    []string   `json:"removed_roles,omitempty"`
	Entitlements    []string   `json:"entitlements"`
	// PreferredLanguage carries the user's stored language preference through from
	// the loaded user row, so callers (e.g. GET /me) need not issue a separate
	// language read (#228). Omitted from JSON when unset.
	PreferredLanguage *string `json:"preferred_language,omitempty"`
	// AvatarURL is the host-supplied avatar URL/key string (#262).
	AvatarURL *string `json:"avatar_url,omitempty"`
}

type AdminListUsersResult struct {
	Users  []AdminUser `json:"users"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

type AdminUserStatus string

type AdminUserSort string

type AdminUserListOptions struct {
	Page        int
	PageSize    int
	Search      string          // ILIKE over username/email/phone_number
	Role        Role            // root_role slug (e.g. "admin"); empty = no role filter
	Status      AdminUserStatus // empty = non-deleted (historical default)
	Sort        AdminUserSort   // empty = created_at
	Desc        bool            // true = descending
	Entitlement string          // empty = no entitlement filter; else provider-backed
}

const (
	AdminUserStatusActive  AdminUserStatus = "active"     // not deleted, not banned
	AdminUserStatusBanned  AdminUserStatus = "banned"     // not deleted, currently banned
	AdminUserStatusDeleted AdminUserStatus = "deleted"    // soft-deleted
	AdminUserStatusAny     AdminUserStatus = "any"        // no deleted/banned predicate
	AdminUserSortCreatedAt AdminUserSort   = "created_at" // default
	AdminUserSortLastLogin AdminUserSort   = "last_login"
	AdminUserSortUsername  AdminUserSort   = "username"
	AdminUserSortEmail     AdminUserSort   = "email"
)
