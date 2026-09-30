package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
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

type ActionAvailability struct {
	Action            string     `json:"action"`
	Allowed           bool       `json:"allowed"`
	Reason            string     `json:"reason"`
	RetryAfterSeconds int64      `json:"retry_after_seconds"`
	NextAllowedAt     *time.Time `json:"next_allowed_at"`
	Limit             *int       `json:"limit"`
	Remaining         *int       `json:"remaining"`
	WindowSeconds     *int64     `json:"window_seconds"`
	CooldownSeconds   *int64     `json:"cooldown_seconds"`
}

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

// StepUpTwoFactorOption is one second factor; VerificationID is the masked
// address its codes go to (null for an authenticator app).
type StepUpTwoFactorOption struct {
	Method         string  `json:"method"`
	IsDefault      bool    `json:"is_default"`
	VerificationID *string `json:"verification_id"`
}

// UserSecurity is the session/step-up/MFA view of the caller's own account,
// nested under UserProfile.Security.
type UserSecurity struct {
	LastAuthenticatedAt               *time.Time              `json:"last_authenticated_at"`
	TimeUntilStepUpRequired           *int64                  `json:"time_until_step_up_required"`
	StepUpRequiredForSensitiveActions bool                    `json:"step_up_required_for_sensitive_actions"`
	StepUpMethods                     []string                `json:"step_up_methods"`
	StepUp2FA                         *StepUpTwoFactorOptions `json:"step_up_2fa"`
	MFAEnabled                        bool                    `json:"mfa_enabled"`
	MFASatisfied                      bool                    `json:"mfa_satisfied"`
	MFAAllowedMethods                 []string                `json:"mfa_allowed_methods"`
}

// UserProfile is the caller's own account as GET /me returns it: the account
// (iam.User) and its sign-in, security and naming state.
type UserProfile struct {
	iam.User
	HasPassword         bool                 `json:"has_password"`
	SolanaLinkedAccount *SolanaLinkedAccount `json:"solana_linked_account"`
	LinkedProviders     []string             `json:"linked_providers"`
	Roles               []string             `json:"roles"`
	Entitlements        []string             `json:"entitlements"`
	Naming              naming.State         `json:"naming"`
	Security            UserSecurity         `json:"security"`
}
