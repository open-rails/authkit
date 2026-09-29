package iam

import "time"

// NewInviteLink is the input of CreateInviteLink. ExpiresIn 0 is the default
// lifetime (72h); longer than 30 days is capped.
type NewInviteLink struct {
	Role      Role
	ExpiresIn time.Duration
}

// InviteLinkCreated is a new single-use invite link. Code is returned once;
// only its hash is stored.
type InviteLinkCreated struct {
	ID        string
	Code      string
	URL       string
	ExpiresAt time.Time
}

// InviteLink is an invite link's metadata (never its code).
type InviteLink struct {
	ID         string
	Role       Role
	InvitedBy  string // "" = issued by the system
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RedeemedAt *time.Time
	RevokedAt  *time.Time
}

// NewAccountInvite invites Email to register. With Group and Role set, the
// registration also grants Role in Group. ExpiresIn 0 is the default (7 days).
type NewAccountInvite struct {
	Email     string
	Group     GroupRef
	Role      Role
	ExpiresIn time.Duration
}

// AccountInviteCreated is a new registration invite. Code is returned once.
type AccountInviteCreated struct {
	ID        string
	Code      string
	URL       string
	Email     string
	ExpiresAt time.Time
}
