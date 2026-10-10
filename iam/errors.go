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
	// ErrSubjectMFARequired refuses a role that needs MFA for an account with
	// no usable second factor.
	ErrSubjectMFARequired Error = errmodel.E(errmodel.CodeSubjectMFARequired)
	// ErrSessionRevoked refuses an identity bound to a session or device key
	// (InSession) that was revoked or expired, as logout, revoke-all, a
	// password change, a ban and deletion all do.
	ErrSessionRevoked Error = errmodel.E(errmodel.CodeSessionRevoked)
	// ErrTokenExpired refuses a token past its exp (beyond the verifier's
	// clock skew).
	ErrTokenExpired Error = errmodel.E(errmodel.CodeTokenExpired)
)

// Groups and naming.
var (
	ErrRenameRateLimited       Error = errmodel.E(errmodel.CodeRenameRateLimited)
	ErrRenamesDisabled         Error = errmodel.E(errmodel.CodeRenamesDisabled)
	ErrRoleNotAssignable       Error = errmodel.E(errmodel.CodeRoleNotAssignable)
	ErrUnknownGroupPersona     Error = errmodel.E(errmodel.CodeUnknownGroupPersona)
	ErrExternalInvitesDisabled Error = errmodel.E(errmodel.CodeExternalInvitesDisabled)
	// ErrInvitationsDisabled: Config.Invitations.Disabled is set.
	ErrInvitationsDisabled Error = errmodel.E(errmodel.CodeInvitationsDisabled)
)

// Custom roles.
var (
	// ErrRoleNotFound: the group has no such role.
	ErrRoleNotFound Error = errmodel.E(errmodel.CodeRoleNotFound)
	// ErrRoleExists refuses a custom role whose name the group already uses.
	ErrRoleExists Error = errmodel.E(errmodel.CodeRoleExists)
	// ErrRoleNotEditable refuses to change or delete a declared role.
	ErrRoleNotEditable Error = errmodel.E(errmodel.CodeRoleNotEditable)
	// ErrRoleLimitReached refuses a custom role past MaxGroupRoles.
	ErrRoleLimitReached Error = errmodel.E(errmodel.CodeRoleLimitReached)
)

// Users.
var (
	ErrEmailInUse             Error = errmodel.E(errmodel.CodeEmailInUse)
	ErrUsernameInUse          Error = errmodel.E(errmodel.CodeUsernameInUse)
	ErrPhoneInUse             Error = errmodel.E(errmodel.CodePhoneInUse)
	ErrInvalidUntil           Error = errmodel.E(errmodel.CodeInvalidUntil)
	ErrAccountRecoveryExpired Error = errmodel.E(errmodel.CodeAccountRecoveryExpired)
	ErrContactNotVerified     Error = errmodel.E(errmodel.CodeContactNotVerified)
	// ErrEntitlementFilterUnavailable refuses UserQuery.Entitlement when the
	// host set no Deps.EntitlementHolders.
	ErrEntitlementFilterUnavailable Error = errmodel.E(errmodel.CodeEntitlementFilterUnavailable)
)

// Sign-in limits (Config.SignIn), both 429 with Retry-After.
var (
	// ErrTooManyAccounts refuses another account from a device past
	// AccountsPerDevice (or AccountsPerAddress).
	ErrTooManyAccounts Error = errmodel.ErrTooManyAccounts
	// ErrTooManyDevices refuses a new device past NewDevicesPerAccount when
	// the account has no proven email or phone to send it a code.
	ErrTooManyDevices Error = errmodel.ErrTooManyDevices
)

// Credentials and applications (the API-key and remote-application
// sentinels live beside their types).
var (
	ErrSigningNotConfigured            Error = errmodel.Internal("signing_not_configured", nil)
	ErrDeviceKeysDisabled              Error = errmodel.E(errmodel.CodeDeviceKeysDisabled)
	ErrRemoteApplicationIssuerConflict Error = errmodel.E(errmodel.CodeRemoteApplicationIssuerConflict)
	ErrReservedIssuer                  Error = errmodel.E(errmodel.CodeReservedIssuer)
)
