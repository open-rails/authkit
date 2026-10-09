package iam

import "time"

// NameResolution always addresses one immutable owner. An alias points directly
// to that owner; CanonicalName reflects its current spelling, never an alias chain.
// AliasExpiresAt is nil for canonical names and permanent aliases; IsAlias tells
// them apart. Expired aliases are not resolutions.
type NameResolution struct {
	ID             string     `json:"id"`
	CanonicalName  string     `json:"canonical_name"`
	IsAlias        bool       `json:"is_alias"`
	AliasExpiresAt *time.Time `json:"alias_expires_at,omitempty"`
}

// NameAdmissionRequest is the username admission hook's operation context.
type NameAdmissionRequest struct {
	UserID string // Empty only before a new account is created.
	// SubjectID is the account making the change: the user, or staff.
	SubjectID     string
	CurrentName   string
	RequestedName string
	Operation     NameOperation
}
type NameOperation string

const (
	NameCreate NameOperation = "create"
	NameRename NameOperation = "rename"
)
