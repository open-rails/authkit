package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/naming"
)

// ActionAvailability reports whether a cooldown-gated action is currently
// allowed; it rides on 429 error metadata.
// Action names carried by ActionAvailability.
const (
	ActionUpdateUsername       = "update_username"
	ActionRequestPasswordReset = "request_password_reset"
	ActionRequestVerification  = "request_verification"
)

type ActionAvailability = errmodel.ActionAvailability

// SolanaLinkedAccount is the AuthKit-owned normalized metadata for a
// SIWS-linked wallet.
type SolanaLinkedAccount struct {
	Provider            string     `json:"provider"`
	Issuer              string     `json:"issuer"`
	Address             string     `json:"address"`
	Verified            bool       `json:"verified"`
	VerifiedAt          *time.Time `json:"verified_at"`
	PrimarySNSName      *string    `json:"primary_sns_name"`
	SNSResolutionStatus string     `json:"sns_resolution_status"`
	SNSResolvedAt       *time.Time `json:"sns_resolved_at"`
	SNSStale            bool       `json:"sns_stale"`
	SNSError            *string    `json:"sns_error"`
}

// StepUpTwoFactorOptions lists the second factors a step-up can use.
type StepUpTwoFactorOptions struct {
	Methods       []string                `json:"methods"`
	DefaultMethod string                  `json:"default_method"`
	Options       []StepUpTwoFactorOption `json:"options"`
}

// StepUpTwoFactorOption is one second factor; Destination is the masked
// address its codes go to (null for an authenticator app).
type StepUpTwoFactorOption struct {
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default"`
	Destination *string `json:"destination"`
}

// StepUpRequired is step_up_required's metadata: how the account can step
// up, the freshness window, and its second factors (MFARequired: a password
// alone never clears the gate).
type StepUpRequired struct {
	StepUpMethods []string                `json:"step_up_methods"`
	MaxAgeSeconds int64                   `json:"max_age_seconds"`
	StepUp2FA     *StepUpTwoFactorOptions `json:"step_up_2fa"`
	MFARequired   bool                    `json:"mfa_required"`
}

// FreshAuth is a session's step-up state: when it last proved its user, and
// how long sensitive actions stay open without a step-up (0 once one is
// required).
type FreshAuth struct {
	LastAuthenticatedAt               *time.Time `json:"last_authenticated_at"`
	StepUpRequiredForSensitiveActions bool       `json:"step_up_required_for_sensitive_actions"`
	StepUpRequiredInSeconds           int64      `json:"step_up_required_in_seconds"`
	AuthMethods                       []string   `json:"auth_methods"`
}

// UserSecurity is GET /me/security: the session's freshness, how the account
// can step up, and its MFA state.
type UserSecurity struct {
	FreshAuth
	StepUpMethods     []string                `json:"step_up_methods"`
	StepUp2FA         *StepUpTwoFactorOptions `json:"step_up_2fa"`
	MFAEnabled        bool                    `json:"mfa_enabled"`
	MFASatisfied      bool                    `json:"mfa_satisfied"`
	MFAAllowedMethods []string                `json:"mfa_allowed_methods"`
}

// LinkedProvider is a sign-in provider linked to the account, with the email
// the provider reported.
type LinkedProvider struct {
	Provider string    `json:"provider"`
	Email    *string   `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

// UserProfile is the caller's own account as GET /me and PATCH /me answer it:
// the account (iam.User), its root role, entitlements, sign-in methods, Solana
// wallet and rename state.
type UserProfile struct {
	iam.User
	RootRole     *iam.Role            `json:"root_role"`
	Entitlements []string             `json:"entitlements"`
	HasPassword  bool                 `json:"has_password"`
	Providers    []LinkedProvider     `json:"providers"`
	SolanaWallet *SolanaLinkedAccount `json:"solana_wallet"`
	Naming       naming.State         `json:"naming"`
}
