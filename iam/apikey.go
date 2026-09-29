package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

var (
	// ErrInvalidAccessToken indicates an API key that does not exist, has a bad
	// secret, or whose owning permission group is gone. Deliberately indistinguishable from
	// a malformed token so callers learn nothing from the error.
	ErrInvalidAccessToken Error = errmodel.E(errmodel.CodeInvalidToken)
	// ErrAccessTokenRevoked indicates the API key was revoked, or its creator
	// can no longer act (banned, deleted or reserved).
	ErrAccessTokenRevoked Error = errmodel.E(errmodel.CodeAccessTokenRevoked)
	// ErrAccessTokenExpired indicates the API key is past its expires_at.
	ErrAccessTokenExpired Error = errmodel.E(errmodel.CodeAccessTokenExpired)
)

// APIKey is an API key's metadata. The secret is returned only by MintAPIKey.
// A key holds one role of its group; Permissions is that role resolved now,
// so editing the role changes every key holding it.
type APIKey struct {
	ID          string // the key's identity: APIKeyActor(ID), verify Claims.APIKeyID
	LookupID    string // the public lookup id embedded in the token
	Name        string
	Role        Role
	Permissions []string
	CreatedBy   string // "" = issued by the operator
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
}

// NewAPIKey is the input of MintAPIKey. ExpiresAt nil means no expiry, capped
// by Config.APIKeys.MaxTTL when set.
type NewAPIKey struct {
	Name      string
	Role      Role
	ExpiresAt *time.Time
}

// APIKeyPrincipal is a resolved, live API key: the group it acts in and the
// permissions of its role at resolution time.
type APIKeyPrincipal struct {
	ID          string
	LookupID    string
	Group       GroupInstance
	Issuer      string // the issuer of the AuthKit deployment holding the key
	Role        Role
	Permissions []string
	ExpiresAt   *time.Time
}
