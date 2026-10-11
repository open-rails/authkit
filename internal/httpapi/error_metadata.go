package httpapi

import (
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
)

// ProviderError is provider_error's metadata: the identity provider's own
// error code.
type ProviderError struct {
	ProviderError string `json:"provider_error"`
}

// TwoFactorRequired is 2fa_required's metadata: the second factor a
// device-key ceremony must carry.
type TwoFactorRequired struct {
	Method string `json:"method"`
}

// ErrorMetadata is the metadata shape of every code that carries metadata
// (zero values); every other code's metadata is null. The contract generator
// publishes it, and the integration suites check every error against it.
func ErrorMetadata() map[errmodel.Code]any {
	return map[errmodel.Code]any{
		errmodel.CodeRateLimited:               errmodel.ActionAvailability{},
		errmodel.CodeServerBusy:                errmodel.RetryAfter{},
		errmodel.CodeTooManyAccounts:           errmodel.SignInLimit{},
		errmodel.CodeTooManyDevices:            errmodel.SignInLimit{},
		errmodel.CodeRenameRateLimited:         errmodel.ActionAvailability{},
		errmodel.CodeStepUpRequired:            authflow.StepUpRequired{},
		errmodel.CodeVerificationRequired:      errmodel.ContactProofRequired{},
		errmodel.CodeContactNotVerified:        errmodel.ContactProofRequired{},
		errmodel.CodeUsernameTooShort:          errmodel.LengthBounds{},
		errmodel.CodeUsernameTooLong:           errmodel.LengthBounds{},
		errmodel.CodePasswordTooShort:          errmodel.LengthBounds{},
		errmodel.CodePasswordTooLong:           errmodel.LengthBounds{},
		errmodel.CodePasswordRequirementsUnmet: errmodel.PasswordRequirements{},
		errmodel.CodeProviderError:             ProviderError{},
		errmodel.CodeTwoFARequired:             TwoFactorRequired{},
		errmodel.CodeAgreementRequired:         errmodel.AgreementsRequired{},
		errmodel.CodeDeletionRefused:           errmodel.DeletionRefusal{},
		errmodel.CodePhoneCountryNotAllowed:    errmodel.PhoneCountry{},
		errmodel.CodeConsentRequired:           errmodel.ConsentRequired{},
	}
}
