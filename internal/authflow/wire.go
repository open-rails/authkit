package authflow

import (
	"time"

	"github.com/open-rails/authkit/iam"
)

// ListPage is the one list envelope: {object:"list", data:[...], next_cursor?}.
// A present next_cursor means another page exists; pass it back as ?cursor=.
type ListPage[T any] struct {
	Object     string `json:"object"`
	Data       []T    `json:"data"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// NewListPage wraps items (never null: an empty page marshals as []).
func NewListPage[T any](items []T, nextCursor string) ListPage[T] {
	if items == nil {
		items = []T{}
	}
	return ListPage[T]{Object: "list", Data: items, NextCursor: nextCursor}
}

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
	Reason            string     `json:"reason,omitempty"`
	RetryAfterSeconds int64      `json:"retry_after_seconds,omitempty"`
	NextAllowedAt     *time.Time `json:"next_allowed_at,omitempty"`
	Limit             *int       `json:"limit,omitempty"`
	Remaining         *int       `json:"remaining,omitempty"`
	WindowSeconds     *int64     `json:"window_seconds,omitempty"`
	CooldownSeconds   *int64     `json:"cooldown_seconds,omitempty"`
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
	Methods       []string                `json:"methods,omitempty"`
	DefaultMethod string                  `json:"default_method,omitempty"`
	Options       []StepUpTwoFactorOption `json:"options,omitempty"`
}

type StepUpTwoFactorOption struct {
	Method         string `json:"method"`
	IsDefault      bool   `json:"is_default,omitempty"`
	VerificationID string `json:"verification_id,omitempty"`
}

// UserSecurity is the session/step-up/MFA view of the caller's own account,
// nested under UserProfile.Security.
type UserSecurity struct {
	LastAuthenticatedAt               *string                 `json:"last_authenticated_at,omitempty"`
	TimeUntilStepUpRequired           *int64                  `json:"time_until_step_up_required,omitempty"`
	StepUpRequiredForSensitiveActions bool                    `json:"step_up_required_for_sensitive_actions"`
	StepUpMethods                     []string                `json:"step_up_methods,omitempty"`
	StepUp2FA                         *StepUpTwoFactorOptions `json:"step_up_2fa,omitempty"`
	MFAEnabled                        bool                    `json:"mfa_enabled"`
	MFASatisfied                      bool                    `json:"mfa_satisfied"`
	MFAAllowedMethods                 []string                `json:"mfa_allowed_methods,omitempty"`
}

// UserProfile is the caller's own account as GET /me returns it: identity,
// contact state, linked providers, roles/entitlements, naming state and the
// security view.
type UserProfile struct {
	ID                  string               `json:"id"`
	Username            string               `json:"username"`
	Email               *string              `json:"email"`
	PhoneNumber         *string              `json:"phone_number"`
	EmailVerified       bool                 `json:"email_verified"`
	PhoneVerified       bool                 `json:"phone_verified"`
	HasPassword         bool                 `json:"has_password"`
	SolanaLinkedAccount *SolanaLinkedAccount `json:"solana_linked_account,omitempty"`
	LinkedProviders     []string             `json:"linked_providers,omitempty"`
	Roles               []string             `json:"roles"`
	Entitlements        []string             `json:"entitlements"`
	AvatarURL           *string              `json:"avatar_url,omitempty"`
	PreferredLanguage   *string              `json:"preferred_language,omitempty"`
	CreatedAt           *string              `json:"created_at,omitempty"`
	Naming              iam.NamingState      `json:"naming"`
	Security            UserSecurity         `json:"security"`
}
