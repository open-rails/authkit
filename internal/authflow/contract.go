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

type PreferredLanguage struct {
	Language string
}
