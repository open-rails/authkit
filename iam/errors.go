package iam

import (
	"errors"

	"github.com/open-rails/authkit/internal/errmodel"
)

// Error is an AuthKit error as the wire sees it. Every error AuthKit returns
// carries one, as does every error DecodeError reads from a response; match
// identities with errors.Is against the sentinels below.
type Error interface {
	error
	// Code is the stable snake_case wire code (internal_error for a server
	// failure; empty for a decoded response that is not an AuthKit error).
	Code() string
	// Status is the HTTP status the catalog fixes for the code.
	Status() int
	// Param names the offending request field, when there is one.
	Param() string
	// Metadata is machine-readable context, such as next_rename_at.
	Metadata() map[string]any
}

// AsError returns the Error in err's chain.
func AsError(err error) (Error, bool) {
	if e := errmodel.As(err); e != nil {
		return e, true
	}
	var r *responseError
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// Lookup.
var (
	ErrUserNotFound              Error = errmodel.E(errmodel.CodeUserNotFound)
	ErrGroupNotFound             Error = errmodel.E(errmodel.CodeGroupNotFound)
	ErrInviteLinkNotFound        Error = errmodel.E(errmodel.CodeInviteLinkNotFound)
	ErrRemoteApplicationNotFound Error = errmodel.E(errmodel.CodeRemoteApplicationNotFound)
)

// Authority.
var (
	ErrInsufficientAuthority      Error = errmodel.E(errmodel.CodeInsufficientAuthority)
	ErrRoleAssignmentEscalation   Error = errmodel.E(errmodel.CodeRoleAssignmentEscalation)
	ErrAccountAuthorityEscalation Error = errmodel.E(errmodel.CodeAccountAuthorityEscalation)
	ErrLastOwner                  Error = errmodel.E(errmodel.CodeLastOwner)
	ErrCannotTargetSelf           Error = errmodel.E(errmodel.CodeCannotTargetSelf)
	ErrTwoFAEnrollmentRequired    Error = errmodel.E(errmodel.CodeTwoFAEnrollmentRequired)
)

// Groups and naming.
var (
	ErrRenameRateLimited       Error = errmodel.E(errmodel.CodeRenameRateLimited)
	ErrRenamesDisabled         Error = errmodel.E(errmodel.CodeRenamesDisabled)
	ErrRoleNotAssignable       Error = errmodel.E(errmodel.CodeRoleNotAssignable)
	ErrUnknownGroupPersona     Error = errmodel.E(errmodel.CodeUnknownGroupPersona)
	ErrExternalInvitesDisabled Error = errmodel.E(errmodel.CodeExternalInvitesDisabled)
)

// Users.
var (
	ErrEmailInUse             Error = errmodel.E(errmodel.CodeEmailInUse)
	ErrUsernameInUse          Error = errmodel.E(errmodel.CodeUsernameInUse)
	ErrPhoneInUse             Error = errmodel.E(errmodel.CodePhoneInUse)
	ErrInvalidUntil           Error = errmodel.E(errmodel.CodeInvalidUntil)
	ErrAccountRecoveryExpired Error = errmodel.E(errmodel.CodeAccountRecoveryExpired)
	ErrContactNotVerified     Error = errmodel.E(errmodel.CodeContactNotVerified)
)

// Credentials and applications (the API-key, service-JWT, delegation and
// remote-application sentinels live beside their types).
var (
	ErrSigningNotConfigured            Error = errmodel.Internal("signing_not_configured", nil)
	ErrDeviceKeysDisabled              Error = errmodel.E(errmodel.CodeDeviceKeysDisabled)
	ErrRemoteApplicationIssuerConflict Error = errmodel.E(errmodel.CodeRemoteApplicationIssuerConflict)
	ErrReservedIssuer                  Error = errmodel.E(errmodel.CodeReservedIssuer)
)
