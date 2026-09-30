package httpapi

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/naming"
)

// Wire types the v1 contract dropped; each goes with its last handler use.

// StepUpResult is a re-authenticated session: a fresh access token whose
// assurance claims match the session.
type StepUpResult struct {
	TokenSet  iam.TokenSet `json:"token_set"`
	FreshAuth FreshAuth    `json:"fresh_auth"`
}

type UsernameChange struct {
	Username string       `json:"username"`
	Naming   naming.State `json:"naming"`
}

type PreferredLanguage struct {
	PreferredLanguage string `json:"preferred_language"`
}

// TwoFactorEnrollResult is a TOTP enrollment started (Secret, OTPAuthURI) or
// a factor enabled (Enabled, BackupCodes on the first factor; TokenSet when
// the enrollment signed the caller in or re-verified the session, with
// FreshAuth for the latter).
type TwoFactorEnrollResult struct {
	Method      string        `json:"method"`
	Enabled     bool          `json:"enabled"`
	Secret      *string       `json:"secret"`
	OTPAuthURI  *string       `json:"otpauth_uri"`
	BackupCodes []string      `json:"backup_codes"`
	TokenSet    *iam.TokenSet `json:"token_set"`
	FreshAuth   *FreshAuth    `json:"fresh_auth"`
}

// RemovedRoles are the roles disabling a factor removed, because they need
// MFA the account no longer has.
type RemovedRoles struct {
	RemovedRoles []RemovedRole `json:"removed_roles"`
}

type RemovedRole struct {
	GroupID   string      `json:"group_id"`
	Persona   iam.Persona `json:"persona"`
	Role      iam.Role    `json:"role"`
	RemovedAt time.Time   `json:"removed_at"`
}

type SolanaLink struct {
	SolanaAddress string `json:"solana_address"`
}

type UsernameRequest struct {
	Username string `json:"username"`
}

type PreferredLanguageRequest struct {
	PreferredLanguage string `json:"preferred_language"`
}

type TwoFactorEnrollRequest struct {
	Method      string  `json:"method"`
	Code        string  `json:"code"`
	PhoneNumber *string `json:"phone_number"`
	Default     bool    `json:"default"`
	FactorID    string  `json:"factor_id"`
}

type TwoFactorFactorQuery struct {
	FactorID string `query:"factor_id"`
}

type MemberAddRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}
