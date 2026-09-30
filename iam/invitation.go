package iam

import (
	"time"

	"github.com/open-rails/authkit/internal/errmodel"
)

// ErrInvitationNotFound indicates no invitation with the id or code exists
// in the group, or none the caller may redeem.
var ErrInvitationNotFound Error = errmodel.E(errmodel.CodeInvitationNotFound)

// NewInvitation is the input of CreateInvitation.
//
// Without Email it is an invite link: a single-use code granting Role (which
// it needs) to the signed-in account that redeems it. With Email, AuthKit
// emails a registration invite to that address: with Role, registering also
// grants it, and an existing account that has verified the address may
// redeem it instead; without Role, in the root group, it only lets the
// address register (root:users:invite).
//
// ExpiresAt nil is the default lifetime: 72 hours for a link, 7 days for an
// email invite. A link lives at most 30 days.
type NewInvitation struct {
	Role      Role
	Email     string
	ExpiresAt *time.Time
}

// Invitation is an invitation's metadata, never its code. Email is "" for a
// link.
type Invitation struct {
	ID         string     `json:"id"`
	GroupID    string     `json:"group_id"`
	Role       Role       `json:"role"`
	Email      string     `json:"email"`
	CreatedBy  string     `json:"created_by"` // "" = issued by the system
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RedeemedAt *time.Time `json:"redeemed_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// InvitationCreated is a new invitation with its code and link, shown this
// once; only the code's hash is stored.
type InvitationCreated struct {
	Invitation Invitation `json:"invitation"`
	Code       string     `json:"code"`
	URL        string     `json:"url"`
}
