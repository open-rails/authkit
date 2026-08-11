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
	// PreferredLanguage is populated by the by-ID lookup (UserByID) only; other
	// lookups leave it nil. Nullable — NULL/unset when the user has no stored
	// language preference.
	PreferredLanguage *string
	// AvatarURL is the host-supplied avatar URL/key string (#262). Blob storage
	// stays host-owned; authkit stores only this string. Populated by the by-ID
	// lookup (UserByID) only, like PreferredLanguage.
	AvatarURL *string
}

// UserRef is a slim user projection (id + display fields) returned by batch
// lookups like Client.UsersByIDs — resolving many user IDs to display data in one
// query, without N+1 single fetches. Part of the wire contract.
//
// It carries Email, so it is the PRIVILEGED batch projection: use it only where
// the caller is entitled to see addresses (admin surfaces, the account's own
// views). For anything rendered to other users — comment authors, gallery
// owners, public profiles — use PublicUserRef / Client.PublicUsersByIDs (#268),
// which has no email field at all.
type UserRef struct {
	ID       string
	Username string // "" if unset
	Email    string // "" if unset
}

// PublicUserRef is the PUBLIC-SAFE batch user projection (#268): the display
// identity of a user as other users may see it. It deliberately has NO email
// field — the type, not an `omitempty` tag or a caller's discipline, is what
// makes it safe to nest inside a response body.
//
// Every field here is public by nature: a username, an avatar, a biography and
// a join date are what a profile page shows. Derived assets (thumbnail sizes,
// CDN rewrites) stay host-owned — authkit stores one avatar string (#262) and
// does not know a host's image pipeline.
type PublicUserRef struct {
	ID string
	// Username is "" when unset OR when the user is a tombstone — see Deleted.
	// Prefer DisplayName over reading this directly.
	Username  string
	AvatarURL string // "" if unset or tombstoned
	Biography string // "" if unset or tombstoned
	CreatedAt time.Time
	// Deleted marks a TOMBSTONE: the id resolved to a soft-deleted account, so
	// the reference is not dangling — but every other field is zero, including
	// CreatedAt. Nothing about a deleted account is published. Callers render
	// DisplayName and show nothing else.
	Deleted bool
}

// DisplayName is the name to render for a user, with the fallback both consumer
// hosts had independently hand-rolled: the username when there is one, else a
// stable, non-identifying `user-<first 8 of id>`. Tombstoned and unnamed users
// take the fallback.
func (r PublicUserRef) DisplayName() string {
	if !r.Deleted && r.Username != "" {
		return r.Username
	}
	return fallbackDisplayName(r.ID)
}

// PublicDisplayName renders id's display name against a PublicUsersByIDs result,
// including for ids the batch did not resolve at all (never-existed accounts,
// which are absent from the map rather than tombstoned). It is the whole
// author-name branch a caller would otherwise write around every lookup.
func PublicDisplayName(refs map[string]PublicUserRef, id string) string {
	if r, ok := refs[id]; ok {
		return r.DisplayName()
	}
	return fallbackDisplayName(id)
}

func fallbackDisplayName(id string) string {
	if len(id) > 8 {
		id = id[:8]
	}
	return "user-" + id
}

// UserLiveness is the per-request account-liveness verdict for one user, plus
// the identity fields that are fresh AS OF that same lookup (#267). It is what
// verify's liveness gate consumes, and what lets a host stop reaching for an
// admin-privileged read just to refresh a username or email onto a request.
//
// The verdict is deliberately BOOLEAN: it does not report whether a denial was
// a ban, a deletion or a reservation. That distinction is an account-status
// question for an authenticated, entitled surface — not something an
// authentication gate should hand back to whoever presented the token.
type UserLiveness struct {
	ID string
	// Allowed is the same account gate that guards token mint at login and
	// refresh: false for deleted, banned and reserved accounts. An expired
	// temporary ban is allowed (and cleared, exactly as the single-user gate
	// clears it).
	Allowed       bool
	Username      string // "" if unset
	Email         string // "" if unset (phone-only accounts have none)
	EmailVerified bool
	AvatarURL     string // "" if unset
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
