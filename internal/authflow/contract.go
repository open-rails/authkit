package authflow

import "github.com/open-rails/authkit/iam"

// InviteRedemption is the group and role a redeemed invite link granted.
type InviteRedemption struct {
	GroupID string
	Persona iam.Persona
	Role    iam.Role
}

type MFAStatus struct {
	Enabled        bool
	Satisfied      bool
	AllowedMethods []iam.TwoFactorMethod
}

type PasswordlessStartRequest struct {
	Identifier         string
	Mode               string
	ReturnTo           string
	PreferredLanguage  string
	AccountInviteToken string
}

// PasswordlessStartResult: Challenge is the start's handle, whether or not a
// code went out (Sent).
type PasswordlessStartResult struct {
	Challenge string
	Sent      bool
	Channel   string
	Code      string
	LinkURL   string
}
