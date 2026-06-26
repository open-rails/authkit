package authkit

import "errors"

// Sentinel errors — the wire-contract error identities shared by the embedded
// engine and (Phase 2) the remote SDK so errors.Is works across transports
// (#138 contract inversion). internal/authcore aliases these.
var (
	ErrBootstrapDatabaseNotEmpty       = errors.New("bootstrap_database_not_empty")
	ErrCannotRemoveLastAdminRole       = errors.New("cannot_remove_last_admin_role")
	ErrCustomClaimsReserved            = errors.New("custom_jwt_reserved_claim")
	ErrCustomJWTReservedType           = errors.New("custom_jwt_reserved_type")
	ErrEmailAlreadyVerified            = errors.New("email_already_verified")
	ErrEmailDeliveryFailed             = errors.New("email_delivery_failed")
	ErrEmailInUse                      = errors.New("email_in_use")
	ErrEmailSenderUnavailable          = errors.New("email_sender_unavailable")
	ErrEmptyCustomClaims               = errors.New("custom_jwt_empty_claims")
	ErrEntitlementFilterUnavailable    = errors.New("authkit: entitlement filtering requires an EntitlementFilterProvider")
	ErrExternalInvitesDisabled         = errors.New("external_invites_disabled")
	ErrGroupNotFound                   = errors.New("permission_group_not_found")
	ErrInsufficientRoleAuthority       = errors.New("insufficient_role_authority")
	ErrInvalidAttributeDef             = errors.New("invalid_attribute_def")
	ErrInvalidBootstrapManifest        = errors.New("invalid_bootstrap_manifest")
	ErrInvalidUntil                    = errors.New("invalid_until")
	ErrInviteEmailMismatch             = errors.New("group_invite_email_mismatch")
	ErrInviteLinkExhausted             = errors.New("group_invite_link_exhausted")
	ErrInviteLinkExpired               = errors.New("group_invite_link_expired")
	ErrInviteLinkNotFound              = errors.New("group_invite_link_not_found")
	ErrInviteLinkRevoked               = errors.New("group_invite_link_revoked")
	ErrMissingSigner                   = errors.New("missing_signer")
	ErrNotGroupMember                  = errors.New("not_group_member")
	ErrOwnerSlugTaken                  = errors.New("owner_slug_taken")
	ErrPasskeyCloneDetected            = errors.New("passkey_clone_detected")
	ErrPasskeyNotFound                 = errors.New("passkey_not_found")
	ErrPasskeyUserVerificationRequired = errors.New("passkey_user_verification_required")
	ErrPasswordlessDisabled            = errors.New("passwordless_disabled")
	ErrPasswordResetRequired           = errors.New("password_reset_required")
	ErrPendingRegistrationNotFound     = errors.New("pending_registration_not_found")
	ErrPhoneAlreadyVerified            = errors.New("phone_already_verified")
	ErrPhoneInUse                      = errors.New("phone_in_use")
	ErrRegistrationDisabled            = errors.New("registration_disabled")
	ErrRemoteApplicationNotFound       = errors.New("remote_application_not_found")
	ErrRenameRateLimited               = errors.New("rename_rate_limited")
	ErrReservedIssuer                  = errors.New("reserved_issuer")
	ErrResourceScopeDenied             = errors.New("resource_scope_denied")
	ErrRoleAssignmentEscalation        = errors.New("role_assignment_escalation")
	ErrSMSDeliveryFailed               = errors.New("sms_delivery_failed")
	ErrSMSSenderUnavailable            = errors.New("sms_unavailable")
	ErrStepUpRequired                  = errors.New("step_up_required")
	ErrTooManyCustomClaims             = errors.New("custom_jwt_too_many_claims")
	ErrTwoFAEnrollmentRequired         = errors.New("2fa_enrollment_required")
	ErrUserBanned                      = errors.New("user_banned")
	ErrUserNotFound                    = errors.New("user_not_found")
	ErrUserRoleNotFound                = errors.New("user_role_not_found")
	ErrVerificationLinkExpired         = errors.New("verification_link_expired")
)

// ErrorForCode maps a wire error code (a sentinel's Error() string) back to the
// sentinel, so a remote client re-derives errors.Is(err, authkit.ErrX) identity
// across the network. Unknown/empty codes return nil — the caller supplies its own
// fallback. The server emits err.Error() as the code; remote/ resolves it here, so
// the wire-error contract has ONE source of truth (#142).
func ErrorForCode(code string) error { return errorsByCode[code] }

// errorsByCode is built once from every sentinel. ponytail: hand-listed because Go
// can't enumerate package vars — a new sentinel needs a line here too; the
// uniqueness check in errors_test.go fails loudly if two share a code.
var errorsByCode = func() map[string]error {
	all := []error{
		ErrBootstrapDatabaseNotEmpty, ErrCannotRemoveLastAdminRole, ErrCustomClaimsReserved,
		ErrCustomJWTReservedType, ErrEmailAlreadyVerified, ErrEmailDeliveryFailed, ErrEmailInUse,
		ErrEmailSenderUnavailable, ErrEmptyCustomClaims, ErrEntitlementFilterUnavailable,
		ErrExternalInvitesDisabled, ErrGroupNotFound, ErrInsufficientRoleAuthority,
		ErrInvalidAttributeDef, ErrInvalidBootstrapManifest, ErrInvalidUntil, ErrInviteEmailMismatch,
		ErrInviteLinkExhausted, ErrInviteLinkExpired, ErrInviteLinkNotFound, ErrInviteLinkRevoked,
		ErrMissingSigner, ErrNotGroupMember, ErrOwnerSlugTaken, ErrPasskeyCloneDetected,
		ErrPasskeyNotFound, ErrPasskeyUserVerificationRequired, ErrPasswordlessDisabled,
		ErrPasswordResetRequired, ErrPendingRegistrationNotFound, ErrPhoneAlreadyVerified,
		ErrPhoneInUse, ErrRegistrationDisabled, ErrRemoteApplicationNotFound, ErrRenameRateLimited,
		ErrReservedIssuer, ErrResourceScopeDenied, ErrRoleAssignmentEscalation, ErrSMSDeliveryFailed,
		ErrSMSSenderUnavailable, ErrStepUpRequired, ErrTooManyCustomClaims, ErrTwoFAEnrollmentRequired,
		ErrUserBanned, ErrUserNotFound, ErrUserRoleNotFound, ErrVerificationLinkExpired,
	}
	m := make(map[string]error, len(all))
	for _, e := range all {
		m[e.Error()] = e
	}
	return m
}()
