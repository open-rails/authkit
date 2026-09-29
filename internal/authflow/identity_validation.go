package authflow

import (
	"github.com/open-rails/authkit/internal/errmodel"
)

// validationCodes are the identity-policy codes ValidationErrorCode reports:
// a 400 whose param names the offending field.
var validationCodes = map[errmodel.Code]bool{
	errmodel.CodeUsernameTooShort: true, errmodel.CodeUsernameTooLong: true, errmodel.CodeUsernameMustStartWithLetter: true,
	errmodel.CodeUsernameCannotContainAt: true, errmodel.CodeUsernameCannotStartWithPlus: true, errmodel.CodeUsernameInvalidCharacters: true,
	errmodel.CodeUsernameInUse: true, errmodel.CodeUsernameNotAllowed: true, errmodel.CodeRenameRateLimited: true,
	errmodel.CodeInvalidEmail: true, errmodel.CodeInvalidPhoneNumber: true, errmodel.CodePasswordTooShort: true, errmodel.CodePasswordTooLong: true,
	errmodel.CodePasswordTooCommon: true, errmodel.CodePasswordContainsIdentifier: true, errmodel.CodePasswordRequirementsUnmet: true,
	errmodel.CodeInvalidPreferredLanguage: true,
}

// ValidationErrorCode returns the identity-policy code err carries, or "" when
// err is not a validation failure.
func ValidationErrorCode(err error) errmodel.Code {
	if code := errmodel.CodeOf(err); validationCodes[code] {
		return code
	}
	return ""
}
