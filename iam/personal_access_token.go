package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrPersonalAccessTokenInvalid does not distinguish an unknown, expired,
// revoked, disabled or incorrectly signed personal token.
var ErrPersonalAccessTokenInvalid Error = errmodel.E(errmodel.CodeInvalidToken)

// PersonalAccessToken belongs to its user, and is confined to one group's
// current permissions. It is not a sign-in session or an organization API key.
type PersonalAccessToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	OwnerUserID string     `json:"owner_user_id"`
	GroupID     string     `json:"group_id"`
	Permissions []Perm     `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// NewPersonalAccessToken requests a subset of the signed-in user's access.
// Permissions are registered concrete names, never wildcards or credentials
// management/MFA-only permissions. The owner comes from the sign-in.
type NewPersonalAccessToken struct {
	Name        string
	GroupID     string
	Permissions []Perm
	ExpiresAt   *time.Time
}

type PersonalAccessTokenCreated struct {
	Token  PersonalAccessToken `json:"token"`
	Secret string              `json:"secret"`
}

// ResolvedPersonalAccessToken reports only current effective permissions.
type ResolvedPersonalAccessToken struct {
	ID          string   `json:"id"`
	OwnerUserID string   `json:"owner_user_id"`
	TenantID    TenantID `json:"tenant_id"`
	Group       Group    `json:"group"`
	Issuer      string   `json:"issuer"`
	Permissions []Perm   `json:"permissions"`
}
