package authflow

import "github.com/open-rails/authkit/iam"

// InviteRedemption is the group and role a redeemed invite link granted.
type InviteRedemption struct {
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
