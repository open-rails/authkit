package authflow

import (
	"sort"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
)

// ProfileInput is what the transport knows that the engine does not: the
// verified claims' username/auth-time/sensitivity and the deployment's
// provider registry.
type ProfileInput struct {
	UserID          string
	ClaimsUsername  string // fallback when the row carries no username
	AuthTime        time.Time
	StepUpSatisfied bool     // the presented token is fresh enough for sensitive actions
	AuthMethods     []string // the presented token's authentication methods (amr)
	// ProviderSupportsStepUp reports which linked providers can re-authenticate.
	ProviderSupportsStepUp func(provider string) bool
}

// StepUpMethods lists how the user can re-authenticate for a sensitive
// action. An account with a second factor re-proves itself only with one
// ("2fa"); any other with its password and every linked provider that
// supports step-up (de-duplicated, sorted). Pure over already-loaded inputs.
func StepUpMethods(hasPassword bool, factors []TwoFactorFactor, providerSlugs []string, supportsStepUp func(string) bool) []string {
	if len(factors) > 0 {
		return []string{"2fa"}
	}
	methods := []string{}
	if hasPassword {
		methods = append(methods, "password")
	}
	seen := make(map[string]struct{}, len(providerSlugs))
	distinct := make([]string, 0, len(providerSlugs))
	for _, provider := range providerSlugs {
		if _, dup := seen[provider]; dup {
			continue
		}
		seen[provider] = struct{}{}
		distinct = append(distinct, provider)
	}
	sort.Strings(distinct)
	for _, provider := range distinct {
		if supportsStepUp != nil && supportsStepUp(provider) {
			methods = append(methods, provider)
		}
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
