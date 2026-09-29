package authflow

import (
	"github.com/open-rails/authkit/iam"
)

// validationCodes are the identity-policy codes ValidationErrorCode reports:
// a 400 whose param names the offending field.
var validationCodes = map[iam.Code]bool{
	iam.CodeUsernameTooShort: true, iam.CodeUsernameTooLong: true, iam.CodeUsernameMustStartWithLetter: true,
	iam.CodeUsernameCannotContainAt: true, iam.CodeUsernameCannotStartWithPlus: true, iam.CodeUsernameInvalidCharacters: true,
	iam.CodeOwnerSlugTaken: true, iam.CodeUsernameNotAllowed: true, iam.CodeRenameRateLimited: true,
	iam.CodeInvalidEmail: true, iam.CodeInvalidPhoneNumber: true, iam.CodePasswordTooShort: true, iam.CodePasswordTooLong: true,
	iam.CodePasswordTooCommon: true, iam.CodePasswordContainsIdentifier: true, iam.CodePasswordRequirementsUnmet: true,
	iam.CodeInvalidPreferredLanguage: true,
}

// ValidationErrorCode returns the identity-policy code err carries, or "" when
// err is not a validation failure.
func ValidationErrorCode(err error) iam.Code {
	if e := iam.AsError(err); e != nil && validationCodes[e.Code] {
		return e.Code
	}
	return ""
}
