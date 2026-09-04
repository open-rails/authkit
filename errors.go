package authkit

import (
	"errors"
	"net/http"

	"github.com/open-rails/authkit/documents"
)

// Sentinel errors — the error identities hosts match with errors.Is (#138
// contract inversion). internal/authcore aliases these.
var (
	ErrApplicationDocumentFetchFailed  = errors.New("application_document_fetch_failed")
	ErrApplicationDocumentInvalid      = errors.New("application_document_invalid")
	ErrApplicationDomainConflict       = errors.New("application_domain_conflict")
	ErrApplicationDomainInvalid        = errors.New("application_domain_invalid")
	ErrApplicationIssuerConflict       = errors.New("application_issuer_conflict")
	ErrApplicationNotDomainRooted      = errors.New("application_not_domain_rooted")
	ErrApplicationRegistrationDisabled = errors.New("application_registration_disabled")
	ErrApplicationSignatureInvalid     = errors.New("application_signature_invalid")
	ErrApplicationSignatureStale       = errors.New("application_signature_stale")
	ErrApplicationSlugConflict         = errors.New("application_slug_conflict")
	ErrApplicationTierInvalid          = errors.New("application_tier_invalid")
	ErrBootstrapDatabaseNotEmpty       = errors.New("bootstrap_database_not_empty")
	ErrGroupSlugApplicationManaged     = errors.New("group_slug_application_managed")
	ErrGroupSlugTaken                  = errors.New("group_slug_taken")
	// #263 generated persona-instance creation.
	ErrGroupSlugReserved    = errors.New("group_slug_reserved")
	ErrGroupSlugInvalid     = errors.New("group_slug_invalid")
	ErrGroupCreationRefused = errors.New("group_creation_refused")
	// #262 first-class avatar URL field.
	ErrAvatarURLInvalid                  = errors.New("avatar_url_invalid")
	ErrCannotRemoveLastAdminRole         = errors.New("cannot_remove_last_admin_role")
	ErrAccountRegistrationInviteConsumed = errors.New("account_registration_invite_consumed")
	ErrAccountRegistrationInviteExpired  = errors.New("account_registration_invite_expired")
	ErrAccountRegistrationInviteNotFound = errors.New("account_registration_invite_not_found")
	ErrAccountRegistrationInviteRevoked  = errors.New("account_registration_invite_revoked")
	ErrCustomClaimsReserved              = errors.New("custom_jwt_reserved_claim")
	ErrCustomJWTReservedType             = errors.New("custom_jwt_reserved_type")
	ErrCustomRoleGrantCrossPersona       = errors.New("custom_role_grant_cross_persona")
	ErrCustomRoleGrantOutsideCatalog     = errors.New("custom_role_grant_outside_catalog")
	ErrCustomRoleIsCatalogRole           = errors.New("custom_role_is_catalog_role")
	ErrCustomRoleNameInvalid             = errors.New("custom_role_name_invalid")
	ErrCustomRolesNotSupported           = errors.New("custom_roles_not_supported")
	ErrEmailAlreadyVerified              = errors.New("email_already_verified")
	ErrEmailDeliveryFailed               = errors.New("email_delivery_failed")
	ErrEmailInUse                        = errors.New("email_in_use")
	ErrEmailSenderUnavailable            = errors.New("email_sender_unavailable")
	ErrEmptyCustomClaims                 = errors.New("custom_jwt_empty_claims")
	ErrEntitlementFilterUnavailable      = errors.New("entitlement_filter_unavailable")
	ErrExternalInvitesDisabled           = errors.New("external_invites_disabled")
	ErrGroupNotFound                     = errors.New("permission_group_not_found")
	ErrInsufficientRoleAuthority         = errors.New("insufficient_role_authority")
	ErrInvalidAttributeDef               = errors.New("invalid_attribute_def")
	ErrInvalidBootstrapManifest          = errors.New("invalid_bootstrap_manifest")
	ErrInvalidExpiry                     = errors.New("invalid_expiry")
	ErrInvalidInvite                     = errors.New("invalid_invite")
	ErrInvalidRole                       = errors.New("invalid_role")
	ErrInvalidUntil                      = errors.New("invalid_until")
	ErrInviteLinkExpired                 = errors.New("group_invite_link_expired")
	ErrInviteLinkNotFound                = errors.New("group_invite_link_not_found")
	ErrInviteLinkRevoked                 = errors.New("group_invite_link_revoked")
	ErrMissingName                       = errors.New("missing_name")
	ErrMissingSigner                     = errors.New("missing_signer")
	ErrNotGroupMember                    = errors.New("not_group_member")
	ErrOwnerSlugTaken                    = errors.New("owner_slug_taken")
	ErrPasskeyCloneDetected              = errors.New("passkey_clone_detected")
	ErrPasskeyNotFound                   = errors.New("passkey_not_found")
	ErrPasskeyUserVerificationRequired   = errors.New("passkey_user_verification_required")
	ErrPasswordlessDisabled              = errors.New("passwordless_disabled")
	ErrDeviceKeysDisabled                = errors.New("device_keys_disabled")
	ErrPasswordResetRequired             = errors.New("password_reset_required")
	ErrPendingRegistrationNotFound       = errors.New("pending_registration_not_found")
	ErrPhoneAlreadyVerified              = errors.New("phone_already_verified")
	ErrPhoneInUse                        = errors.New("phone_in_use")
	ErrUsernameInUse                     = errors.New("username_in_use")
	ErrRegistrationDisabled              = errors.New("registration_disabled")
	ErrRemoteApplicationIssuerConflict   = errors.New("remote_application_issuer_conflict")
	ErrRemoteApplicationNotFound         = errors.New("remote_application_not_found")
	ErrRenameRateLimited                 = errors.New("rename_rate_limited")
	ErrReservedIssuer                    = errors.New("reserved_issuer")
	ErrRoleAssignmentEscalation          = errors.New("role_assignment_escalation")
	ErrAccountAuthorityEscalation        = errors.New("account_authority_escalation")
	ErrRoleNotAssignable                 = errors.New("role_not_assignable")
	ErrSMSDeliveryFailed                 = errors.New("sms_delivery_failed")
	ErrSMSSenderUnavailable              = errors.New("sms_unavailable")
	ErrStepUpRequired                    = errors.New("step_up_required")
	ErrTooManyCustomClaims               = errors.New("custom_jwt_too_many_claims")
	ErrTwoFAFactorExists                 = errors.New("2fa_factor_exists")
	ErrTwoFAEnrollmentRequired           = errors.New("2fa_enrollment_required")
	ErrUnknownGroupPersona               = errors.New("unknown_group_persona")
	ErrUnknownRole                       = errors.New("unknown_role")
	ErrUserBanned                        = errors.New("user_banned")
	ErrUserNotFound                      = errors.New("user_not_found")
	ErrUserReferenced                    = errors.New("user_referenced")
	ErrUserRoleNotFound                  = errors.New("user_role_not_found")
	ErrVerificationLinkExpired           = errors.New("verification_link_expired")
	ErrSIWSAddressMismatch               = errors.New("siws_address_mismatch")
	ErrSIWSChallengeExpired              = errors.New("siws_challenge_expired")
	ErrSIWSChallengeMismatch             = errors.New("siws_challenge_mismatch")
	ErrSIWSChallengeNotFound             = errors.New("siws_challenge_not_found")
	ErrSIWSDomainInvalid                 = errors.New("siws_domain_invalid")
	ErrSIWSSignatureInvalid              = errors.New("siws_signature_invalid")
	ErrSIWSTimestampInvalid              = errors.New("siws_timestamp_invalid")
	ErrWalletAlreadyLinked               = errors.New("wallet_already_linked")
	ErrWalletChangeRequiresUnlink        = errors.New("wallet_change_requires_unlink")
	ErrProviderAlreadyLinked             = errors.New("provider_already_linked")
	ErrProviderChangeRequiresUnlink      = errors.New("provider_change_requires_unlink")
)

// ErrorForCode maps a wire error code (a sentinel's Error() string) back to the
// sentinel, so a remote client re-derives errors.Is(err, authkit.ErrX) identity
// across the network. Unknown/empty codes return nil — the caller supplies its own
// fallback. The server emits err.Error() as the code; remote/ resolves it here, so
// the wire-error contract has ONE source of truth (#142).
func ErrorForCode(code string) error { return errorsByCode[code] }

// CodeForError resolves an error to its wire code by walking the error chain: it
// returns the first sentinel's .Error() for which errors.Is(err, sentinel) holds,
// or "" if none match. Unlike keying off err.Error() directly, this handles WRAPPED
// sentinels (e.g. fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, cause)) — the server
// emits that code so the remote client re-derives errors.Is(err, ErrX) identity and
// the status classification stays correct across the wire (#197).
func CodeForError(err error) string {
	if err == nil {
		return ""
	}
	for _, sentinel := range errorSentinels {
		if errors.Is(err, sentinel) {
			return sentinel.Error()
		}
	}
	return ""
}

// sentinelHTTPStatus assigns each sentinel its HTTP status for HTTPStatus (#213).
// DERIVED from the authhttp handlers' existing errors.Is chains (2026-07-04
// inventory) — this table transcribes shipped behavior, it does not invent it.
// Sentinels absent here default to 422 Unprocessable Entity, matching the
// management transport's historical classification of domain errors.
var sentinelHTTPStatus = map[error]int{
	// 401 — authentication failures.
	ErrApplicationSignatureInvalid: http.StatusUnauthorized,
	ErrApplicationSignatureStale:   http.StatusUnauthorized,
	ErrUserBanned:                  http.StatusUnauthorized,
	ErrPasswordResetRequired:       http.StatusUnauthorized,
	ErrSIWSChallengeNotFound:       http.StatusUnauthorized,
	ErrSIWSChallengeExpired:        http.StatusUnauthorized,
	ErrSIWSChallengeMismatch:       http.StatusUnauthorized,
	ErrSIWSSignatureInvalid:        http.StatusUnauthorized,
	ErrSIWSDomainInvalid:           http.StatusUnauthorized,
	ErrSIWSTimestampInvalid:        http.StatusUnauthorized,
	// 403 — authenticated but not allowed.
	ErrApplicationRegistrationDisabled: http.StatusForbidden,
	ErrRegistrationDisabled:            http.StatusForbidden,
	ErrPasswordlessDisabled:            http.StatusForbidden,
	ErrDeviceKeysDisabled:              http.StatusForbidden,
	ErrTwoFAEnrollmentRequired:         http.StatusForbidden,
	ErrTwoFAFactorExists:               http.StatusConflict,
	ErrStepUpRequired:                  http.StatusForbidden,
	ErrExternalInvitesDisabled:         http.StatusForbidden,
	ErrInsufficientRoleAuthority:       http.StatusForbidden,
	ErrRoleAssignmentEscalation:        http.StatusForbidden,
	ErrAccountAuthorityEscalation:      http.StatusForbidden,
	ErrGroupSlugReserved:               http.StatusForbidden,
	ErrGroupCreationRefused:            http.StatusForbidden,
	// 404 — subject not found.
	ErrUserNotFound:                http.StatusNotFound,
	ErrPendingRegistrationNotFound: http.StatusNotFound,
	ErrPasskeyNotFound:             http.StatusNotFound,
	ErrGroupNotFound:               http.StatusNotFound,
	ErrRemoteApplicationNotFound:   http.StatusNotFound,
	ErrInviteLinkNotFound:          http.StatusNotFound,
	// 409 — conflicts with current state.
	ErrApplicationDomainConflict:       http.StatusConflict,
	ErrApplicationIssuerConflict:       http.StatusConflict,
	ErrRemoteApplicationIssuerConflict: http.StatusConflict,
	ErrApplicationNotDomainRooted:      http.StatusConflict,
	ErrApplicationSlugConflict:         http.StatusConflict,
	ErrGroupSlugApplicationManaged:     http.StatusConflict,
	ErrGroupSlugTaken:                  http.StatusConflict,
	ErrEmailAlreadyVerified:            http.StatusConflict,
	ErrPhoneAlreadyVerified:            http.StatusConflict,
	ErrCannotRemoveLastAdminRole:       http.StatusConflict,
	ErrWalletAlreadyLinked:             http.StatusConflict,
	ErrWalletChangeRequiresUnlink:      http.StatusConflict,
	ErrProviderAlreadyLinked:           http.StatusConflict,
	ErrUserReferenced:                  http.StatusConflict,
	ErrProviderChangeRequiresUnlink:    http.StatusConflict,

	// 410 — expired one-shot links.
	ErrVerificationLinkExpired: http.StatusGone,
	// 429 — rate limits.
	ErrRenameRateLimited: http.StatusTooManyRequests,
	// 400 — malformed / invalid input.
	ErrApplicationDocumentInvalid:     http.StatusBadRequest,
	ErrApplicationDomainInvalid:       http.StatusBadRequest,
	ErrApplicationTierInvalid:         http.StatusBadRequest,
	ErrInvalidUntil:                   http.StatusBadRequest,
	ErrAvatarURLInvalid:               http.StatusBadRequest,
	ErrGroupSlugInvalid:               http.StatusBadRequest,
	ErrEmailInUse:                     http.StatusBadRequest,
	ErrPhoneInUse:                     http.StatusBadRequest,
	ErrUsernameInUse:                  http.StatusBadRequest,
	ErrEntitlementFilterUnavailable:   http.StatusBadRequest,
	ErrInvalidRemoteApplication:       http.StatusBadRequest,
	ErrReservedIssuer:                 http.StatusBadRequest,
	ErrInviteLinkExpired:              http.StatusBadRequest,
	ErrInviteLinkRevoked:              http.StatusBadRequest,
	ErrSIWSAddressMismatch:            http.StatusBadRequest,
	ErrOwnerSlugTaken:                 http.StatusBadRequest,
	ErrRoleNotAssignable:              http.StatusBadRequest,
	ErrInvalidRole:                    http.StatusBadRequest,
	ErrUnknownRole:                    http.StatusBadRequest,
	ErrMissingName:                    http.StatusBadRequest,
	ErrInvalidInvite:                  http.StatusBadRequest,
	ErrInvalidExpiry:                  http.StatusBadRequest,
	ErrUnknownGroupPersona:            http.StatusBadRequest,
	ErrCustomRolesNotSupported:        http.StatusBadRequest,
	ErrCustomRoleNameInvalid:          http.StatusBadRequest,
	ErrCustomRoleIsCatalogRole:        http.StatusBadRequest,
	ErrCustomRoleGrantCrossPersona:    http.StatusBadRequest,
	ErrCustomRoleGrantOutsideCatalog:  http.StatusBadRequest,
	documents.ErrInvalidReference:     http.StatusBadRequest,
	documents.ErrInvalidType:          http.StatusBadRequest,
	documents.ErrInvalidDigest:        http.StatusBadRequest,
	documents.ErrDuplicateReference:   http.StatusBadRequest,
	documents.ErrTooManyReferences:    http.StatusBadRequest,
	documents.ErrReferencesTooLarge:   http.StatusBadRequest,
	documents.ErrWrongTokenType:       http.StatusBadRequest,
	documents.ErrReservedAttribute:    http.StatusBadRequest,
	documents.ErrInvalidEnvelope:      http.StatusBadRequest,
	documents.ErrPayloadTooLarge:      http.StatusBadRequest,
	documents.ErrMalformedJWS:         http.StatusBadRequest,
	documents.ErrWrongJOSEType:        http.StatusBadRequest,
	documents.ErrUnsupportedAlgorithm: http.StatusBadRequest,
	documents.ErrUnsupportedSigner:    http.StatusBadRequest,
	documents.ErrUnknownKey:           http.StatusBadRequest,
	documents.ErrInvalidSignature:     http.StatusBadRequest,
	documents.ErrDigestMismatch:       http.StatusBadRequest,
	documents.ErrIssuerMismatch:       http.StatusBadRequest,
	documents.ErrAudienceMismatch:     http.StatusBadRequest,
	documents.ErrTypeMismatch:         http.StatusBadRequest,
	documents.ErrUntrustedIssuer:      http.StatusForbidden,
	documents.ErrDigestCollision:      http.StatusConflict,
	documents.ErrUnauthorized:         http.StatusUnauthorized,
	documents.ErrNotFound:             http.StatusNotFound,
	documents.ErrFetch:                http.StatusBadGateway,
	documents.ErrRedirect:             http.StatusBadGateway,
	// 502/503 — delivery/dependency failures.
	ErrApplicationDocumentFetchFailed: http.StatusBadGateway,
	ErrEmailDeliveryFailed:            http.StatusBadGateway,
	ErrSMSDeliveryFailed:              http.StatusBadGateway,
	ErrEmailSenderUnavailable:         http.StatusServiceUnavailable,
	ErrSMSSenderUnavailable:           http.StatusServiceUnavailable,
}

// HTTPStatus maps an error to its HTTP status and wire code (#213): the ONE
// chain-aware mapper for consumers calling Client methods directly and for the
// management transport, so hosts stop re-implementing the errors.Is chains
// authkit already encodes. Non-sentinel errors return (500, "internal_error");
// sentinels without an explicit status entry return 422 with their code.
// (The authhttp handlers keep their own chains where they deliberately emit
// context-specific wire codes — e.g. last-admin-role maps to a different code
// on the group routes than the sentinel's own.)
func HTTPStatus(err error) (int, string) {
	code := CodeForError(err)
	if code == "" {
		return http.StatusInternalServerError, "internal_error"
	}
	if status, ok := sentinelHTTPStatus[ErrorForCode(code)]; ok {
		return status, code
	}
	return http.StatusUnprocessableEntity, code
}

// ErrorCodes returns every registered wire code (each sentinel's Error()
// string), for parity guards between this registry and transport code tables.
func ErrorCodes() []string {
	out := make([]string, 0, len(errorSentinels))
	for _, sentinel := range errorSentinels {
		out = append(out, sentinel.Error())
	}
	return out
}

// errorSentinels is the single hand-listed source of truth for both errorsByCode
// and CodeForError. NOTE: hand-listed because Go can't enumerate package vars —
// a new sentinel needs a line here too; the uniqueness check in errors_test.go
// fails loudly if two share a code.
var errorSentinels = []error{
	ErrApplicationDocumentFetchFailed, ErrApplicationDocumentInvalid, ErrApplicationDomainConflict, ErrApplicationDomainInvalid,
	ErrApplicationIssuerConflict, ErrApplicationNotDomainRooted, ErrApplicationRegistrationDisabled,
	ErrApplicationSignatureInvalid, ErrApplicationSignatureStale, ErrApplicationSlugConflict,
	ErrApplicationTierInvalid, ErrGroupSlugApplicationManaged, ErrGroupSlugTaken,
	ErrGroupSlugReserved, ErrGroupSlugInvalid, ErrGroupCreationRefused, ErrAvatarURLInvalid,
	ErrBootstrapDatabaseNotEmpty, ErrCannotRemoveLastAdminRole, ErrAccountRegistrationInviteConsumed,
	ErrAccountRegistrationInviteExpired, ErrAccountRegistrationInviteNotFound,
	ErrAccountRegistrationInviteRevoked, ErrCustomClaimsReserved,
	ErrCustomJWTReservedType, ErrDelegationRefused, ErrEmailAlreadyVerified, ErrEmailDeliveryFailed, ErrEmailInUse,
	ErrEmailSenderUnavailable, ErrEmptyCustomClaims, ErrEntitlementFilterUnavailable,
	ErrExternalInvitesDisabled, ErrGroupNotFound, ErrInsufficientRoleAuthority,
	ErrInvalidAttributeDef, ErrInvalidBootstrapManifest, ErrInvalidUntil,
	ErrInviteLinkExpired, ErrInviteLinkNotFound, ErrInviteLinkRevoked,
	ErrMissingSigner, ErrNotGroupMember, ErrOwnerSlugTaken, ErrPasskeyCloneDetected,
	ErrPasskeyNotFound, ErrPasskeyUserVerificationRequired, ErrPasswordlessDisabled, ErrDeviceKeysDisabled,
	ErrPasswordResetRequired, ErrPendingRegistrationNotFound, ErrPhoneAlreadyVerified,
	ErrPhoneInUse, ErrUsernameInUse, ErrRegistrationDisabled, ErrRemoteApplicationNotFound, ErrRemoteApplicationIssuerConflict, ErrRenameRateLimited,
	ErrReservedIssuer, ErrRoleAssignmentEscalation, ErrAccountAuthorityEscalation, ErrSMSDeliveryFailed,
	ErrSMSSenderUnavailable, ErrStepUpRequired, ErrTooManyCustomClaims, ErrTwoFAEnrollmentRequired, ErrTwoFAFactorExists,
	ErrUserBanned, ErrUserNotFound, ErrUserReferenced, ErrUserRoleNotFound, ErrVerificationLinkExpired,

	ErrSIWSAddressMismatch, ErrSIWSChallengeExpired, ErrSIWSChallengeMismatch, ErrSIWSChallengeNotFound, ErrSIWSDomainInvalid,
	ErrSIWSSignatureInvalid, ErrSIWSTimestampInvalid, ErrWalletAlreadyLinked, ErrWalletChangeRequiresUnlink,
	ErrProviderAlreadyLinked, ErrProviderChangeRequiresUnlink,
	// #247: permission-group hardening — role-assignability + custom-role +
	// invite/api-key input errors, promoted from ad hoc strings so authhttp maps
	// them via errors.Is instead of strings.Contains.
	ErrRoleNotAssignable, ErrInvalidRole, ErrUnknownRole, ErrMissingName,
	ErrInvalidInvite, ErrInvalidExpiry, ErrUnknownGroupPersona,
	ErrCustomRolesNotSupported, ErrCustomRoleNameInvalid, ErrCustomRoleIsCatalogRole,
	ErrCustomRoleGrantCrossPersona, ErrCustomRoleGrantOutsideCatalog,
	// #253-#255: generic immutable signed-document contract.
	documents.ErrInvalidReference, documents.ErrInvalidType, documents.ErrInvalidDigest,
	documents.ErrDuplicateReference, documents.ErrTooManyReferences, documents.ErrReferencesTooLarge,
	documents.ErrWrongTokenType, documents.ErrReservedAttribute, documents.ErrInvalidEnvelope,
	documents.ErrPayloadTooLarge, documents.ErrMalformedJWS, documents.ErrWrongJOSEType,
	documents.ErrUnsupportedAlgorithm, documents.ErrUnsupportedSigner, documents.ErrUnknownKey,
	documents.ErrInvalidSignature, documents.ErrDigestMismatch, documents.ErrIssuerMismatch,
	documents.ErrAudienceMismatch, documents.ErrTypeMismatch, documents.ErrUntrustedIssuer,
	documents.ErrUnauthorized, documents.ErrNotFound, documents.ErrFetch, documents.ErrRedirect,
	// #260: authkit-owned signed-document store.
	documents.ErrDigestCollision,
}

// errorsByCode is built once from every sentinel in errorSentinels.
var errorsByCode = func() map[string]error {
	m := make(map[string]error, len(errorSentinels))
	for _, e := range errorSentinels {
		m[e.Error()] = e
	}
	return m
}()
