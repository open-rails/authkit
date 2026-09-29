package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

type RedeemGroupInviteLinkResult struct {
	Persona      iam.Persona
	InstanceSlug string
	Role         iam.Role
}

type AccountRegistrationInvite struct {
	ID         string
	Email      string
	InvitedBy  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ConsumedAt *time.Time
	ConsumedBy *string
	// Persona/InstanceSlug/Role describe an OPTIONAL group role the code also grants
	// on consume (#147 register+join). Empty for a plain registration invite.
	Persona      iam.Persona
	InstanceSlug string
	Role         iam.Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type CreateAccountRegistrationInviteRequest struct {
	Email     string
	InvitedBy string
	ExpiresIn time.Duration
	// Persona/InstanceSlug/Role, when all set, make this a register+join invite: the
	// minted code ALSO grants the given role in that permission group on consume
	// (#147). The minting actor must hold that group's members:manage (no-escalation);
	// a role-carrying invite does NOT require general root:users:invite. Leave empty
	// for a plain registration invite (root:users:invite gated).
	Persona      iam.Persona
	InstanceSlug string
	Role         iam.Role
}

type AccountRegistrationInviteCreated struct {
	ID        string
	Code      string
	URL       string
	Email     string
	ExpiresAt time.Time
	// Persona/InstanceSlug/Role echo the optional group grant carried by the code.
	Persona      iam.Persona
	InstanceSlug string
	Role         iam.Role
}

type MFAStatus struct {
	Enabled        bool
	Satisfied      bool
	AllowedMethods []string
}

type PasswordlessStartRequest struct {
	Identifier         string
	Mode               string
	ReturnTo           string
	PreferredLanguage  string
	AccountInviteToken string
}

type PasswordlessStartResult struct {
	Sent    bool
	Channel string
	Code    string
	LinkURL string
}

// CustomRoleDef defines (or redefines) a per-group custom role: its grant
// patterns, all in the group's persona namespace, and whether holding it
// requires an enrolled second factor (mirrors Role.RequiresMFA, #247).
type CustomRoleDef struct {
	Role        iam.Role
	Permissions []string
	RequiresMFA bool
}

type PreferredLanguage struct {
	Language string
}
