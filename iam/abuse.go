package iam

import "github.com/open-rails/authkit/internal/errmodel"

// CaptchaWidget is what a browser renders to prove it is not a bot before a
// start that sends a code (Deps.Captcha): GET /capabilities names it.
type CaptchaWidget struct {
	// Provider is the widget's provider: "turnstile" or "hcaptcha".
	Provider string `json:"provider"`
	// SiteKey is the provider's public key for this site.
	SiteKey string `json:"site_key"`
}

// ErrCaptchaFailed is what a Deps.Captcha verifier returns when the provider
// refused a token (wrong, expired or spent): captcha_failed (400). Any other
// verifier error is captcha_unavailable (503).
var ErrCaptchaFailed Error = errmodel.E(errmodel.CodeCaptchaFailed)

// RefuseSMSDestination is what an SMSSender returns when it or its provider
// will not text a number (a premium or high-risk range, a region the account
// may not reach, a recipient who opted out): phone_number_not_allowed (400),
// with reason as metadata.reason. It is the number's answer, never a sign
// the sender is unhealthy.
func RefuseSMSDestination(reason string) error {
	return errmodel.E(errmodel.CodePhoneNumberNotAllowed, errmodel.WithDetails(errmodel.Refusal{Reason: reason}))
}

// ErrSMSDestinationRefused matches every RefuseSMSDestination error.
var ErrSMSDestinationRefused Error = errmodel.E(errmodel.CodePhoneNumberNotAllowed)
