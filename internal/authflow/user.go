package authflow

import (
	"time"
)

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

// UserDirectoryDetail is what the admin user views add to an iam.User: root
// roles (RemovedRoles are stored roles no longer in the catalog) and
// entitlements.
type UserDirectoryDetail struct {
	Roles        []string
	RemovedRoles []string
	Entitlements []string
}
