package authflow

import (
	"sort"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/contact"
)

// ProfileInput is what the transport knows that the engine does not: the
// verified claims' username/auth-time/sensitivity and the deployment's
// provider registry.
type ProfileInput struct {
	UserID          string
	ClaimsUsername  string // fallback when the row carries no username
	AuthTime        time.Time
	StepUpSatisfied bool // the presented token is fresh enough for sensitive actions
	// EnabledProviders lists the deployment's login providers;
	// ProviderSupportsStepUp reports which linked providers can re-authenticate.
	EnabledProviders       []string
	ProviderSupportsStepUp func(provider string) bool
}

// StepUpMethods lists how the user can re-authenticate for a sensitive
// action: password, an enabled second factor, and every linked provider that
// supports step-up (de-duplicated, sorted). Pure over already-loaded inputs.
func StepUpMethods(hasPassword bool, settings *TwoFactorSettings, providerSlugs []string, supportsStepUp func(string) bool) []string {
	methods := []string{}
	if hasPassword {
		methods = append(methods, "password")
	}
	if settings != nil && settings.Enabled {
		methods = append(methods, "2fa")
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

// NewStepUpTwoFactorOptions lists the second factors a step-up can use, with the
// code destination masked. Nil when 2FA is not enabled.
func NewStepUpTwoFactorOptions(settings *TwoFactorSettings) *StepUpTwoFactorOptions {
	if settings == nil || !settings.Enabled {
		return nil
	}
	factors := settings.Factors
	if len(factors) == 0 && strings.TrimSpace(settings.Method) != "" {
		factors = []TwoFactorFactor{{Method: strings.TrimSpace(settings.Method), PhoneNumber: settings.PhoneNumber, IsDefault: true, Enabled: true}}
	}
	if len(factors) == 0 {
		return nil
	}
	out := &StepUpTwoFactorOptions{}
	for _, factor := range factors {
		method := strings.ToLower(strings.TrimSpace(factor.Method))
		if !factor.Enabled || !ValidTwoFactorStepUpMethod(method) {
			continue
		}
		option := StepUpTwoFactorOption{Method: method, IsDefault: factor.IsDefault}
		switch method {
		case "email":
			if factor.Email != nil {
				option.VerificationID = contact.MaskDestination(*factor.Email)
			}
		case "sms":
			if factor.PhoneNumber != nil {
				option.VerificationID = contact.MaskDestination(*factor.PhoneNumber)
			}
		}
		out.Methods = append(out.Methods, method)
		out.Options = append(out.Options, option)
		if factor.IsDefault {
			out.DefaultMethod = method
		}
	}
	if len(out.Methods) == 0 {
		return nil
	}
	if out.DefaultMethod == "" {
		out.DefaultMethod = out.Methods[0]
		out.Options[0].IsDefault = true
	}
	return out
}

// ValidTwoFactorStepUpMethod reports whether method can satisfy a step-up.
func ValidTwoFactorStepUpMethod(method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "email", "sms", "totp":
		return true
	default:
		return false
	}
}
