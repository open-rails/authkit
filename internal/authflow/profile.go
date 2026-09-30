package authflow

import (
	"slices"
	"sort"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
)

// ProfileInput is what the transport knows that the engine does not: the
// verified claims' username, auth time and sensitivity.
type ProfileInput struct {
	UserID          string
	ClaimsUsername  string // fallback when the row carries no username
	AuthTime        time.Time
	StepUpSatisfied bool     // the presented token is fresh enough for sensitive actions
	AuthMethods     []string // the presented token's authentication methods (amr)
}

// StepUpCredentials is what an account can re-authenticate with.
type StepUpCredentials struct {
	Password     bool
	SecondFactor bool // an enabled second factor
	Passkey      bool
	Email, SMS   bool // a proven address a code can reach now
	Solana       bool // a linked wallet
	// Providers are the linked providers that prove a fresh sign-in.
	Providers []string
}

// Methods lists the step-up methods that clear the sensitive-action gate. An
// account with a second factor steps up with it or a passkey, which is
// multi-factor itself; any other steps up with each way it signs in.
func (c StepUpCredentials) Methods() []string {
	methods := []string{}
	add := func(ok bool, method string) {
		if ok && !slices.Contains(methods, method) {
			methods = append(methods, method)
		}
	}
	if c.SecondFactor {
		add(true, "2fa")
		add(c.Passkey, "passkey")
		return methods
	}
	add(c.Password, "password")
	add(c.Passkey, "passkey")
	add(c.Email, "email")
	add(c.SMS, "sms")
	add(c.Solana, "solana")
	providers := slices.Clone(c.Providers)
	sort.Strings(providers)
	for _, provider := range providers {
		add(true, provider)
	}
	return methods
}

// StepUpFactors lists the second factors a step-up can use: none unless 2FA
// is enabled.
func StepUpFactors(settings *TwoFactorSettings) []TwoFactorFactor {
	if settings == nil || !settings.Enabled {
		return []TwoFactorFactor{}
	}
	return WireFactors(settings.Factors)
}

// NewTwoFactorStatus is the account's second-factor state; nil settings is
// an account that never enrolled.
func NewTwoFactorStatus(settings *TwoFactorSettings, allowed []iam.TwoFactorMethod) TwoFactorStatus {
	if allowed == nil {
		allowed = []iam.TwoFactorMethod{}
	}
	if settings == nil {
		return TwoFactorStatus{Factors: []TwoFactorFactor{}, AllowedMethods: allowed}
	}
	return TwoFactorStatus{
		Enabled:              settings.Enabled,
		Factors:              WireFactors(settings.Factors),
		AllowedMethods:       allowed,
		BackupCodesRemaining: len(settings.BackupCodes),
	}
}

// WireFactor is f as the wire shows it, its code destination masked.
func WireFactor(f MFAFactor) TwoFactorFactor {
	out := TwoFactorFactor{ID: f.ID, Method: f.Method, IsDefault: f.IsDefault}
	destination := f.Email
	if f.Method == "sms" {
		destination = f.PhoneNumber
	}
	if destination != nil && f.Method != "totp" {
		masked := contact.MaskDestination(*destination)
		out.Destination = &masked
	}
	return out
}

// WireFactors is WireFactor over factors, never nil.
func WireFactors(factors []MFAFactor) []TwoFactorFactor {
	out := make([]TwoFactorFactor, 0, len(factors))
	for _, f := range factors {
		out = append(out, WireFactor(f))
	}
	return out
}
