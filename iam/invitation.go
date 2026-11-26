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
// it needs) to the account that uses it, signed in or signing up with it. With
// Email, AuthKit emails an invitation to that address: with Role, registering
// with its code grants it, and an existing account that has verified the
// address may redeem it instead; without Role, in the root or owning tenant
// group, it only admits a registration (the corresponding users:invite
// permission). Either code admits a registration under invite_only.
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
	TenantID   TenantID   `json:"tenant_id"`
	ID         string     `json:"id"`
	GroupID    string     `json:"group_id"`
	Role       Role       `json:"role"`
	Email      *string    `json:"email"`      // nil = a link, not an email invitation
	CreatedBy  *string    `json:"created_by"` // nil = issued by the system
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RedeemedAt *time.Time `json:"redeemed_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// InvitationCreated is a new invitation with its code and link, shown this
// once; only the code's hash is stored. Emailed reports that an email
// invitation was sent: its code went to the address alone, so Code and URL
// are empty, and registering that address with it proves the address.
// Otherwise (a link, or email unavailable) the inviter shares URL privately:
// whoever uses it first gets the role.
type InvitationCreated struct {
	Invitation Invitation `json:"invitation"`
	Code       string     `json:"code"`
	URL        string     `json:"url"`
	Emailed    bool       `json:"emailed"`
}
