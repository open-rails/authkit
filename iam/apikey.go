package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

var (
	// ErrAPIKeyInvalid indicates an API key that is malformed, does not exist,
	// has a bad secret, or whose owning permission group is gone: one answer so
	// callers learn nothing from the error.
	ErrAPIKeyInvalid Error = errmodel.E(errmodel.CodeAPIKeyInvalid)
	// ErrAPIKeyRevoked indicates the API key was revoked, or its creator
	// can no longer act (banned or deleted).
	ErrAPIKeyRevoked Error = errmodel.E(errmodel.CodeAPIKeyRevoked)
	// ErrAPIKeyExpired indicates the API key is past its expires_at.
	ErrAPIKeyExpired Error = errmodel.E(errmodel.CodeAPIKeyExpired)
	// ErrAPIKeyNotFound indicates no key with the id exists in the group.
	ErrAPIKeyNotFound Error = errmodel.E(errmodel.CodeAPIKeyNotFound)
)

// APIKey is an API key's metadata; the secret is shown only by CreateAPIKey.
// A key holds one role of its group; Permissions is that role resolved now,
// so editing the role changes every key holding it.
type APIKey struct {
	ID          string     `json:"id"`        // the key's id: APIKeyIdentity(ID), verify Claims.APIKeyID
	LookupID    string     `json:"lookup_id"` // the public lookup id embedded in the token
	GroupID     string     `json:"group_id"`
	Name        string     `json:"name"`
	Role        Role       `json:"role"`
	Permissions []Perm     `json:"permissions"`
	CreatedBy   *string    `json:"created_by"` // nil = issued by the system
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// APIKeyCreated is a new key and its token, shown this once.
type APIKeyCreated struct {
	APIKey APIKey `json:"api_key"`
	Secret string `json:"secret"`
}

// NewAPIKey is the input of CreateAPIKey. ExpiresAt nil means no expiry,
// capped by Config.APIKeys.MaxTTL when set.
type NewAPIKey struct {
	Name      string
	Role      Role
	ExpiresAt *time.Time
}

// ResolvedAPIKey is a resolved, live API key: the group it acts in and the
// permissions of its role at resolution time.
type ResolvedAPIKey struct {
	ID          string     `json:"id"`
	LookupID    string     `json:"lookup_id"`
	Group       Group      `json:"group"`
	Issuer      string     `json:"issuer"` // the issuer of the AuthKit deployment holding the key
	Role        Role       `json:"role"`
	Permissions []Perm     `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
}
