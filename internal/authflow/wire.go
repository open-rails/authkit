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

// TwoFactorFactor is one second factor, the one shape sign-in, step-up and
// management share; each addresses it by ID. Destination is the masked address
// its codes go to (null for an authenticator app).
type TwoFactorFactor struct {
	ID          string  `json:"id"`
	Method      string  `json:"method"`
	IsDefault   bool    `json:"is_default"`
	Destination *string `json:"destination"`
}

// TwoFactorStatus is the account's second factors and the methods it may
// enroll.
type TwoFactorStatus struct {
	Enabled              bool                  `json:"enabled"`
	Factors              []TwoFactorFactor     `json:"factors"`
	AllowedMethods       []iam.TwoFactorMethod `json:"allowed_methods"`
	BackupCodesRemaining int                   `json:"backup_codes_remaining"`
}

// StepUpRequired is step_up_required's metadata: the methods that clear the
// gate, the freshness window, and the second factors a "2fa" step-up can use.
type StepUpRequired struct {
	StepUpMethods []string          `json:"step_up_methods"`
	MaxAgeSeconds int64             `json:"max_age_seconds"`
	Factors       []TwoFactorFactor `json:"factors"`
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
// can step up, and its second factors.
type UserSecurity struct {
	FreshAuth
	StepUpMethods []string        `json:"step_up_methods"`
	TwoFactor     TwoFactorStatus `json:"two_factor"`
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
