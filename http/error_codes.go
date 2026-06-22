package authhttp

import core "github.com/open-rails/authkit/core"

// ErrorCode is a stable AuthKit HTTP wire error code.
type ErrorCode string

// String returns the wire value.
func (c ErrorCode) String() string { return string(c) }

const (
	// ErrTwoFAChallengeFailed is the 2fa_challenge_failed AuthKit HTTP wire error code.
	ErrTwoFAChallengeFailed ErrorCode = "2fa_challenge_failed"

	// ErrTwoFASendFailed is the 2fa_send_failed AuthKit HTTP wire error code.
	ErrTwoFASendFailed ErrorCode = "2fa_send_failed"

	// ErrAbandonFailed is the abandon_failed AuthKit HTTP wire error code.
	ErrAbandonFailed ErrorCode = "abandon_failed"

	// ErrAccessTokenCreateFailed is the access_token_create_failed AuthKit HTTP wire error code.
	ErrAccessTokenCreateFailed ErrorCode = "access_token_create_failed"

	// ErrAccessTokenListFailed is the access_token_list_failed AuthKit HTTP wire error code.
	ErrAccessTokenListFailed ErrorCode = "access_token_list_failed"

	// ErrAccessTokenNotFound is the access_token_not_found AuthKit HTTP wire error code.
	ErrAccessTokenNotFound ErrorCode = "access_token_not_found"

	// ErrAccessTokenRevokeFailed is the access_token_revoke_failed AuthKit HTTP wire error code.
	ErrAccessTokenRevokeFailed ErrorCode = "access_token_revoke_failed"

	// ErrAccountAlreadyClaimed is the account_already_claimed AuthKit HTTP wire error code.
	ErrAccountAlreadyClaimed ErrorCode = "account_already_claimed"

	// ErrAccountClaimOrgFailed is the account_claim_org_failed AuthKit HTTP wire error code.
	ErrAccountClaimOrgFailed ErrorCode = "account_claim_org_failed"

	// ErrAccountClaimUserFailed is the account_claim_user_failed AuthKit HTTP wire error code.
	ErrAccountClaimUserFailed ErrorCode = "account_claim_user_failed"

	// ErrAccountExistsLinkRequired is the account_exists_link_required AuthKit HTTP wire error code.
	ErrAccountExistsLinkRequired ErrorCode = "account_exists_link_required"

	// ErrAccountParkFailed is the account_park_failed AuthKit HTTP wire error code.
	ErrAccountParkFailed ErrorCode = "account_park_failed"

	// ErrAccountRestrictFailed is the account_restrict_failed AuthKit HTTP wire error code.
	ErrAccountRestrictFailed ErrorCode = "account_restrict_failed"

	// ErrAccountUnrestrictFailed is the account_unrestrict_failed AuthKit HTTP wire error code.
	ErrAccountUnrestrictFailed ErrorCode = "account_unrestrict_failed"

	// ErrAddMemberFailed is the add_member_failed AuthKit HTTP wire error code.
	ErrAddMemberFailed ErrorCode = "add_member_failed"

	// ErrAddressMismatch is the address_mismatch AuthKit HTTP wire error code.
	ErrAddressMismatch ErrorCode = "address_mismatch"

	// ErrAddressRequired is the address_required AuthKit HTTP wire error code.
	ErrAddressRequired ErrorCode = "address_required"

	// ErrAssignPlatformRoleFailed is the assign_platform_role_failed AuthKit HTTP wire error code.
	ErrAssignPlatformRoleFailed ErrorCode = "assign_platform_role_failed"

	// ErrAssignRoleFailed is the assign_role_failed AuthKit HTTP wire error code.
	ErrAssignRoleFailed ErrorCode = "assign_role_failed"

	// ErrAttributeDefNotFound is the attribute_def_not_found AuthKit HTTP wire error code.
	ErrAttributeDefNotFound ErrorCode = "attribute_def_not_found"

	// ErrAttributeDefRegisterFailed is the attribute_def_register_failed AuthKit HTTP wire error code.
	ErrAttributeDefRegisterFailed ErrorCode = "attribute_def_register_failed"

	// ErrAttributeDefResolveFailed is the attribute_def_resolve_failed AuthKit HTTP wire error code.
	ErrAttributeDefResolveFailed ErrorCode = "attribute_def_resolve_failed"

	// ErrAuthRequiredForLink is the auth_required_for_link AuthKit HTTP wire error code.
	ErrAuthRequiredForLink ErrorCode = "auth_required_for_link"

	// ErrAuthenticationFailed is the authentication_failed AuthKit HTTP wire error code.
	ErrAuthenticationFailed ErrorCode = "authentication_failed"

	// ErrAuthenticationRequired is the authentication_required AuthKit HTTP wire error code.
	ErrAuthenticationRequired ErrorCode = "authentication_required"

	// ErrAuthkitNotInitialized is the authkit_not_initialized AuthKit HTTP wire error code.
	ErrAuthkitNotInitialized ErrorCode = "authkit_not_initialized"

	// ErrAuthlogUnavailable is the authlog_unavailable AuthKit HTTP wire error code.
	ErrAuthlogUnavailable ErrorCode = "authlog_unavailable"

	// ErrCancelFailed is the cancel_failed AuthKit HTTP wire error code.
	ErrCancelFailed ErrorCode = "cancel_failed"

	// ErrCannotRemoveLastOwner is the cannot_remove_last_owner AuthKit HTTP wire error code.
	ErrCannotRemoveLastOwner ErrorCode = "cannot_remove_last_owner"

	// ErrCannotRemovePersonalOrgOwner is the cannot_remove_personal_org_owner AuthKit HTTP wire error code.
	ErrCannotRemovePersonalOrgOwner ErrorCode = "cannot_remove_personal_org_owner"

	// ErrCannotUnlinkLastLoginMethod is the cannot_unlink_last_login_method AuthKit HTTP wire error code.
	ErrCannotUnlinkLastLoginMethod ErrorCode = "cannot_unlink_last_login_method"

	// ErrChallengeExpired is the challenge_expired AuthKit HTTP wire error code.
	ErrChallengeExpired ErrorCode = "challenge_expired"

	// ErrChallengeFailed is the challenge_failed AuthKit HTTP wire error code.
	ErrChallengeFailed ErrorCode = "challenge_failed"

	// ErrChallengeVerifyFailed is the challenge_verify_failed AuthKit HTTP wire error code.
	ErrChallengeVerifyFailed ErrorCode = "challenge_verify_failed"

	// ErrDatabaseError is the database_error AuthKit HTTP wire error code.
	ErrDatabaseError ErrorCode = "database_error"

	// ErrDefineRoleFailed is the define_role_failed AuthKit HTTP wire error code.
	ErrDefineRoleFailed ErrorCode = "define_role_failed"

	// ErrDeleteRoleFailed is the delete_role_failed AuthKit HTTP wire error code.
	ErrDeleteRoleFailed ErrorCode = "delete_role_failed"

	// ErrDisableTwoFAFailed is the disable_2fa_failed AuthKit HTTP wire error code.
	ErrDisableTwoFAFailed ErrorCode = "disable_2fa_failed"

	// ErrDuplicateResource is the duplicate_resource AuthKit HTTP wire error code.
	ErrDuplicateResource ErrorCode = "duplicate_resource"

	// ErrEmailAlreadyVerified is the email_already_verified AuthKit HTTP wire error code.
	ErrEmailAlreadyVerified ErrorCode = "email_already_verified"

	// ErrEmailDeliveryFailed is the email_delivery_failed AuthKit HTTP wire error code.
	ErrEmailDeliveryFailed ErrorCode = "email_delivery_failed"

	// ErrEmailInUse is the email_in_use AuthKit HTTP wire error code.
	ErrEmailInUse ErrorCode = "email_in_use"

	// ErrEmailNotVerified is the email_not_verified AuthKit HTTP wire error code.
	ErrEmailNotVerified ErrorCode = "email_not_verified"

	// ErrEmailPasswordResetUnavailable is the email_password_reset_unavailable AuthKit HTTP wire error code.
	ErrEmailPasswordResetUnavailable ErrorCode = "email_password_reset_unavailable"

	// ErrEmailRegistrationUnavailable is the email_registration_unavailable AuthKit HTTP wire error code.
	ErrEmailRegistrationUnavailable ErrorCode = "email_registration_unavailable"

	// ErrEmailSenderUnavailable is the email_sender_unavailable AuthKit HTTP wire error code.
	ErrEmailSenderUnavailable ErrorCode = "email_sender_unavailable"

	// ErrEmailUnavailable is the email_unavailable AuthKit HTTP wire error code.
	ErrEmailUnavailable ErrorCode = "email_unavailable"

	// ErrEmailUnchanged is the email_unchanged AuthKit HTTP wire error code.
	ErrEmailUnchanged ErrorCode = "email_unchanged"

	// ErrEmailVerificationFailed is the email_verification_failed AuthKit HTTP wire error code.
	ErrEmailVerificationFailed ErrorCode = "email_verification_failed"

	// ErrEmailVerificationUnavailable is the email_verification_unavailable AuthKit HTTP wire error code.
	ErrEmailVerificationUnavailable ErrorCode = "email_verification_unavailable"

	// ErrEnableTwoFAFailed is the enable_2fa_failed AuthKit HTTP wire error code.
	ErrEnableTwoFAFailed ErrorCode = "enable_2fa_failed"

	// ErrEntitlementFilterUnavailable is the entitlement_filter_unavailable AuthKit HTTP wire error code.
	ErrEntitlementFilterUnavailable ErrorCode = "entitlement_filter_unavailable"

	// ErrExchangeFailed is the exchange_failed AuthKit HTTP wire error code.
	ErrExchangeFailed ErrorCode = "exchange_failed"

	// ErrFailedToBan is the failed_to_ban AuthKit HTTP wire error code.
	ErrFailedToBan ErrorCode = "failed_to_ban"

	// ErrFailedToDelete is the failed_to_delete AuthKit HTTP wire error code.
	ErrFailedToDelete ErrorCode = "failed_to_delete"

	// ErrFailedToList is the failed_to_list AuthKit HTTP wire error code.
	ErrFailedToList ErrorCode = "failed_to_list"

	// ErrFailedToListDeletedUsers is the failed_to_list_deleted_users AuthKit HTTP wire error code.
	ErrFailedToListDeletedUsers ErrorCode = "failed_to_list_deleted_users"

	// ErrFailedToListSignins is the failed_to_list_signins AuthKit HTTP wire error code.
	ErrFailedToListSignins ErrorCode = "failed_to_list_signins"

	// ErrFailedToListUsers is the failed_to_list_users AuthKit HTTP wire error code.
	ErrFailedToListUsers ErrorCode = "failed_to_list_users"

	// ErrFailedToLogout is the failed_to_logout AuthKit HTTP wire error code.
	ErrFailedToLogout ErrorCode = "failed_to_logout"

	// ErrFailedToRequestEmailChange is the failed_to_request_email_change AuthKit HTTP wire error code.
	ErrFailedToRequestEmailChange ErrorCode = "failed_to_request_email_change"

	// ErrFailedToRequestPhoneChange is the failed_to_request_phone_change AuthKit HTTP wire error code.
	ErrFailedToRequestPhoneChange ErrorCode = "failed_to_request_phone_change"

	// ErrFailedToRestoreUser is the failed_to_restore_user AuthKit HTTP wire error code.
	ErrFailedToRestoreUser ErrorCode = "failed_to_restore_user"

	// ErrFailedToRevoke is the failed_to_revoke AuthKit HTTP wire error code.
	ErrFailedToRevoke ErrorCode = "failed_to_revoke"

	// ErrFailedToRevokeAll is the failed_to_revoke_all AuthKit HTTP wire error code.
	ErrFailedToRevokeAll ErrorCode = "failed_to_revoke_all"

	// ErrFailedToRevokeSessions is the failed_to_revoke_sessions AuthKit HTTP wire error code.
	ErrFailedToRevokeSessions ErrorCode = "failed_to_revoke_sessions"

	// ErrFailedToSetPassword is the failed_to_set_password AuthKit HTTP wire error code.
	ErrFailedToSetPassword ErrorCode = "failed_to_set_password"

	// ErrFailedToUnban is the failed_to_unban AuthKit HTTP wire error code.
	ErrFailedToUnban ErrorCode = "failed_to_unban"

	// ErrFailedToUnlink is the failed_to_unlink AuthKit HTTP wire error code.
	ErrFailedToUnlink ErrorCode = "failed_to_unlink"

	// ErrFailedToUpdateBiography is the failed_to_update_biography AuthKit HTTP wire error code.
	ErrFailedToUpdateBiography ErrorCode = "failed_to_update_biography"

	// ErrFailedToUpdateEmail is the failed_to_update_email AuthKit HTTP wire error code.
	ErrFailedToUpdateEmail ErrorCode = "failed_to_update_email"

	// ErrFailedToUpdatePreferredLocale is the failed_to_update_preferred_locale AuthKit HTTP wire error code.
	ErrFailedToUpdatePreferredLocale ErrorCode = "failed_to_update_preferred_locale"

	// ErrFailedToUpdateUsername is the failed_to_update_username AuthKit HTTP wire error code.
	ErrFailedToUpdateUsername ErrorCode = "failed_to_update_username"

	// ErrForbidden is the forbidden AuthKit HTTP wire error code.
	ErrForbidden ErrorCode = "forbidden"

	// ErrHashFailed is the hash_failed AuthKit HTTP wire error code.
	ErrHashFailed ErrorCode = "hash_failed"

	// ErrInvalidAddress is the invalid_address AuthKit HTTP wire error code.
	ErrInvalidAddress ErrorCode = "invalid_address"

	// ErrInvalidAllowedOrigins is the invalid_allowed_origins AuthKit HTTP wire error code.
	ErrInvalidAllowedOrigins ErrorCode = "invalid_allowed_origins"

	// ErrInvalidBaseURL is the invalid_base_url AuthKit HTTP wire error code.
	ErrInvalidBaseURL ErrorCode = "invalid_base_url"

	// ErrInvalidChallenge is the invalid_challenge AuthKit HTTP wire error code.
	ErrInvalidChallenge ErrorCode = "invalid_challenge"

	// ErrInvalidCode is the invalid_code AuthKit HTTP wire error code.
	ErrInvalidCode ErrorCode = "invalid_code"

	// ErrInvalidCredentials is the invalid_credentials AuthKit HTTP wire error code.
	ErrInvalidCredentials ErrorCode = "invalid_credentials"

	// ErrInvalidDefinition is the invalid_definition AuthKit HTTP wire error code.
	ErrInvalidDefinition ErrorCode = "invalid_definition"

	// ErrInvalidEmail is the invalid_email AuthKit HTTP wire error code.
	ErrInvalidEmail ErrorCode = core.ErrCodeInvalidEmail

	// ErrInvalidExpiresAt is the invalid_expires_at AuthKit HTTP wire error code.
	ErrInvalidExpiresAt ErrorCode = "invalid_expires_at"

	// ErrInvalidExpiry is the invalid_expiry AuthKit HTTP wire error code.
	ErrInvalidExpiry ErrorCode = "invalid_expiry"

	// ErrInvalidFederationIssuer is the invalid_federation_issuer AuthKit HTTP wire error code.
	ErrInvalidFederationIssuer ErrorCode = "invalid_federation_issuer"

	// ErrInvalidFederationTrustSource is the invalid_federation_trust_source AuthKit HTTP wire error code.
	ErrInvalidFederationTrustSource ErrorCode = "invalid_federation_trust_source"

	// ErrInvalidIdentifier is the invalid_identifier AuthKit HTTP wire error code.
	ErrInvalidIdentifier ErrorCode = "invalid_identifier"

	// ErrInvalidMessageEncoding is the invalid_message_encoding AuthKit HTTP wire error code.
	ErrInvalidMessageEncoding ErrorCode = "invalid_message_encoding"

	// ErrInvalidMethod is the invalid_method AuthKit HTTP wire error code.
	ErrInvalidMethod ErrorCode = "invalid_method"

	// ErrInvalidOrExpiredCode is the invalid_or_expired_code AuthKit HTTP wire error code.
	ErrInvalidOrExpiredCode ErrorCode = "invalid_or_expired_code"

	// ErrInvalidOrExpiredResetSession is the invalid_or_expired_reset_session AuthKit HTTP wire error code.
	ErrInvalidOrExpiredResetSession ErrorCode = "invalid_or_expired_reset_session"

	// ErrInvalidOrExpiredToken is the invalid_or_expired_token AuthKit HTTP wire error code.
	ErrInvalidOrExpiredToken ErrorCode = "invalid_or_expired_token"

	// ErrInvalidOrgOwner is the invalid_org_owner AuthKit HTTP wire error code.
	ErrInvalidOrgOwner ErrorCode = "invalid_org_owner"

	// ErrInvalidOrgSlug is the invalid_org_slug AuthKit HTTP wire error code.
	ErrInvalidOrgSlug ErrorCode = "invalid_org_slug"

	// ErrInvalidOwnerNamespaceTransition is the invalid_owner_namespace_transition AuthKit HTTP wire error code.
	ErrInvalidOwnerNamespaceTransition ErrorCode = "invalid_owner_namespace_transition"

	// ErrInvalidPassword is the invalid_password AuthKit HTTP wire error code.
	ErrInvalidPassword ErrorCode = "invalid_password"

	// ErrInvalidPhoneNumber is the invalid_phone_number AuthKit HTTP wire error code.
	ErrInvalidPhoneNumber ErrorCode = core.ErrCodeInvalidPhoneNumber

	// ErrInvalidPreferredLocale is the invalid_preferred_locale AuthKit HTTP wire error code.
	ErrInvalidPreferredLocale ErrorCode = "invalid_preferred_locale"

	// ErrInvalidProvider is the invalid_provider AuthKit HTTP wire error code.
	ErrInvalidProvider ErrorCode = "invalid_provider"

	// ErrInvalidRefreshToken is the invalid_refresh_token AuthKit HTTP wire error code.
	ErrInvalidRefreshToken ErrorCode = "invalid_refresh_token"

	// ErrInvalidRequest is the invalid_request AuthKit HTTP wire error code.
	ErrInvalidRequest ErrorCode = "invalid_request"

	// ErrInvalidResource is the invalid_resource AuthKit HTTP wire error code.
	ErrInvalidResource ErrorCode = "invalid_resource"

	// ErrInvalidRole is the invalid_role AuthKit HTTP wire error code.
	ErrInvalidRole ErrorCode = "invalid_role"

	// ErrInvalidSignature is the invalid_signature AuthKit HTTP wire error code.
	ErrInvalidSignature ErrorCode = "invalid_signature"

	// ErrInvalidSignatureEncoding is the invalid_signature_encoding AuthKit HTTP wire error code.
	ErrInvalidSignatureEncoding ErrorCode = "invalid_signature_encoding"

	// ErrInvalidSlug is the invalid_slug AuthKit HTTP wire error code.
	ErrInvalidSlug ErrorCode = "invalid_slug"

	// ErrInvalidState is the invalid_state AuthKit HTTP wire error code.
	ErrInvalidState ErrorCode = "invalid_state"

	// ErrInvalidToken is the invalid_token AuthKit HTTP wire error code.
	ErrInvalidToken ErrorCode = "invalid_token"

	// ErrInvalidTrustSource is the invalid_trust_source AuthKit HTTP wire error code.
	ErrInvalidTrustSource ErrorCode = "invalid_trust_source"

	// ErrInvalidUI is the invalid_ui AuthKit HTTP wire error code.
	ErrInvalidUI ErrorCode = "invalid_ui"

	// ErrInvalidUntil is the invalid_until AuthKit HTTP wire error code.
	ErrInvalidUntil ErrorCode = "invalid_until"

	// ErrInvalidVersion is the invalid_version AuthKit HTTP wire error code.
	ErrInvalidVersion ErrorCode = "invalid_version"

	// ErrInviteNotFound is the invite_not_found AuthKit HTTP wire error code.
	ErrInviteNotFound ErrorCode = "invite_not_found"

	// ErrIssuerOwnedByOtherOrg is the issuer_owned_by_other_org AuthKit HTTP wire error code.
	ErrIssuerOwnedByOtherOrg ErrorCode = "issuer_owned_by_other_org"

	// ErrIssuerReserved is the issuer_reserved AuthKit HTTP wire error code.
	ErrIssuerReserved ErrorCode = "issuer_reserved"

	// ErrLinkFailed is the link_failed AuthKit HTTP wire error code.
	ErrLinkFailed ErrorCode = "link_failed"

	// ErrMemberPermissionsLookupFailed is the member_permissions_lookup_failed AuthKit HTTP wire error code.
	ErrMemberPermissionsLookupFailed ErrorCode = "member_permissions_lookup_failed"

	// ErrMemberRolesLookupFailed is the member_roles_lookup_failed AuthKit HTTP wire error code.
	ErrMemberRolesLookupFailed ErrorCode = "member_roles_lookup_failed"

	// ErrMissingFields is the missing_fields AuthKit HTTP wire error code.
	ErrMissingFields ErrorCode = "missing_fields"

	// ErrMissingName is the missing_name AuthKit HTTP wire error code.
	ErrMissingName ErrorCode = "missing_name"

	// ErrMissingRole is the missing_role AuthKit HTTP wire error code.
	ErrMissingRole ErrorCode = "missing_role"

	// ErrMissingSessionID is the missing_session_id AuthKit HTTP wire error code.
	ErrMissingSessionID ErrorCode = "missing_session_id"

	// ErrMissingSidClaim is the missing_sid_claim AuthKit HTTP wire error code.
	ErrMissingSidClaim ErrorCode = "missing_sid_claim"

	// ErrNoEmail is the no_email AuthKit HTTP wire error code.
	ErrNoEmail ErrorCode = "no_email"

	// ErrNoPendingEmailChange is the no_pending_email_change AuthKit HTTP wire error code.
	ErrNoPendingEmailChange ErrorCode = "no_pending_email_change"

	// ErrNoPendingPhoneChange is the no_pending_phone_change AuthKit HTTP wire error code.
	ErrNoPendingPhoneChange ErrorCode = "no_pending_phone_change"

	// ErrNotAuthenticated is the not_authenticated AuthKit HTTP wire error code.
	ErrNotAuthenticated ErrorCode = "not_authenticated"

	// ErrNotFound is the not_found AuthKit HTTP wire error code.
	ErrNotFound ErrorCode = "not_found"

	// ErrNotOrgMember is the not_org_member AuthKit HTTP wire error code.
	ErrNotOrgMember ErrorCode = "not_org_member"

	// ErrOIDCBeginFailed is the oidc_begin_failed AuthKit HTTP wire error code.
	ErrOIDCBeginFailed ErrorCode = "oidc_begin_failed"

	// ErrOIDCExchangeFailed is the oidc_exchange_failed AuthKit HTTP wire error code.
	ErrOIDCExchangeFailed ErrorCode = "oidc_exchange_failed"

	// ErrOrgAlreadyClaimed is the org_already_claimed AuthKit HTTP wire error code.
	ErrOrgAlreadyClaimed ErrorCode = "org_already_claimed"

	// ErrOrgCreateFailed is the org_create_failed AuthKit HTTP wire error code.
	ErrOrgCreateFailed ErrorCode = "org_create_failed"

	// ErrOrgDetailFailed is the org_detail_failed AuthKit HTTP wire error code.
	ErrOrgDetailFailed ErrorCode = "org_detail_failed"

	// ErrOrgInviteAcceptFailed is the org_invite_accept_failed AuthKit HTTP wire error code.
	ErrOrgInviteAcceptFailed ErrorCode = "org_invite_accept_failed"

	// ErrOrgInviteCreateFailed is the org_invite_create_failed AuthKit HTTP wire error code.
	ErrOrgInviteCreateFailed ErrorCode = "org_invite_create_failed"

	// ErrOrgInviteDeclineFailed is the org_invite_decline_failed AuthKit HTTP wire error code.
	ErrOrgInviteDeclineFailed ErrorCode = "org_invite_decline_failed"

	// ErrOrgInviteRevokeFailed is the org_invite_revoke_failed AuthKit HTTP wire error code.
	ErrOrgInviteRevokeFailed ErrorCode = "org_invite_revoke_failed"

	// ErrOrgInviteExpired is the org_invite_expired AuthKit HTTP wire error code.
	ErrOrgInviteExpired ErrorCode = "org_invite_expired"

	// ErrOrgInviteNotPending is the org_invite_not_pending AuthKit HTTP wire error code.
	ErrOrgInviteNotPending ErrorCode = "org_invite_not_pending"

	// ErrOrgInvitesLookupFailed is the org_invites_lookup_failed AuthKit HTTP wire error code.
	ErrOrgInvitesLookupFailed ErrorCode = "org_invites_lookup_failed"

	// ErrOrgLimitExceeded is the org_limit_exceeded AuthKit HTTP wire error code.
	ErrOrgLimitExceeded ErrorCode = "org_limit_exceeded"

	// ErrOrgLookupFailed is the org_lookup_failed AuthKit HTTP wire error code.
	ErrOrgLookupFailed ErrorCode = "org_lookup_failed"

	// ErrOrgMembershipLookupFailed is the org_membership_lookup_failed AuthKit HTTP wire error code.
	ErrOrgMembershipLookupFailed ErrorCode = "org_membership_lookup_failed"

	// ErrOrgMembershipsLookupFailed is the org_memberships_lookup_failed AuthKit HTTP wire error code.
	ErrOrgMembershipsLookupFailed ErrorCode = "org_memberships_lookup_failed"

	// ErrOrgManagementDisabled is the org_management_disabled AuthKit HTTP wire error code.
	ErrOrgManagementDisabled ErrorCode = "org_management_disabled"

	// ErrOrgNotFound is the org_not_found AuthKit HTTP wire error code.
	ErrOrgNotFound ErrorCode = "org_not_found"

	// ErrOrgRecoverFailed is the org_recover_failed AuthKit HTTP wire error code.
	ErrOrgRecoverFailed ErrorCode = "org_recover_failed"

	// ErrOrgRenameFailed is the org_rename_failed AuthKit HTTP wire error code.
	ErrOrgRenameFailed ErrorCode = "org_rename_failed"

	// ErrOrgRestoreFailed is the org_restore_failed AuthKit HTTP wire error code.
	ErrOrgRestoreFailed ErrorCode = "org_restore_failed"

	// ErrOrgRolesLookupFailed is the org_roles_lookup_failed AuthKit HTTP wire error code.
	ErrOrgRolesLookupFailed ErrorCode = "org_roles_lookup_failed"

	// ErrOrgSoftDeleteFailed is the org_soft_delete_failed AuthKit HTTP wire error code.
	ErrOrgSoftDeleteFailed ErrorCode = "org_soft_delete_failed"

	// ErrOrgTransferOwnerFailed is the org_transfer_owner_failed AuthKit HTTP wire error code.
	ErrOrgTransferOwnerFailed ErrorCode = "org_transfer_owner_failed"

	// ErrOrgsListFailed is the orgs_list_failed AuthKit HTTP wire error code.
	ErrOrgsListFailed ErrorCode = "orgs_list_failed"

	// ErrOrgsLookupFailed is the orgs_lookup_failed AuthKit HTTP wire error code.
	ErrOrgsLookupFailed ErrorCode = "orgs_lookup_failed"

	// ErrOwnerMembershipRequired is the owner_membership_required AuthKit HTTP wire error code.
	ErrOwnerMembershipRequired ErrorCode = "owner_membership_required"

	// ErrOwnerNamespaceInfoFailed is the owner_namespace_info_failed AuthKit HTTP wire error code.
	ErrOwnerNamespaceInfoFailed ErrorCode = "owner_namespace_info_failed"

	// ErrOwnerSlugTaken is the owner_slug_taken AuthKit HTTP wire error code.
	ErrOwnerSlugTaken ErrorCode = core.ErrCodeOwnerSlugTaken

	// ErrOwnerUserNotFound is the owner_user_not_found AuthKit HTTP wire error code.
	ErrOwnerUserNotFound ErrorCode = "owner_user_not_found"

	// ErrPasswordChangeFailed is the password_change_failed AuthKit HTTP wire error code.
	ErrPasswordChangeFailed ErrorCode = "password_change_failed"

	// ErrPasswordResetRequestFailed is the password_reset_request_failed AuthKit HTTP wire error code.
	ErrPasswordResetRequestFailed ErrorCode = "password_reset_request_failed"

	// ErrPasswordResetRequired is the password_reset_required AuthKit HTTP wire error code.
	ErrPasswordResetRequired ErrorCode = "password_reset_required"

	// ErrPasswordTooShort is the password_too_short AuthKit HTTP wire error code.
	ErrPasswordTooShort ErrorCode = core.ErrCodePasswordTooShort

	// ErrPendingRegistrationNotFound is the pending_registration_not_found AuthKit HTTP wire error code.
	ErrPendingRegistrationNotFound ErrorCode = "pending_registration_not_found"

	// ErrPermissionCheckFailed is the permission_check_failed AuthKit HTTP wire error code.
	ErrPermissionCheckFailed ErrorCode = "permission_check_failed"

	// ErrPermissionGrantDenied is the permission_grant_denied AuthKit HTTP wire error code.
	ErrPermissionGrantDenied ErrorCode = "permission_grant_denied"

	// ErrPermissionValidateFailed is the permission_validate_failed AuthKit HTTP wire error code.
	ErrPermissionValidateFailed ErrorCode = "permission_validate_failed"

	// ErrPermissionsLookupFailed is the permissions_lookup_failed AuthKit HTTP wire error code.
	ErrPermissionsLookupFailed ErrorCode = "permissions_lookup_failed"

	// ErrPersonalOrgLocked is the personal_org_locked AuthKit HTTP wire error code.
	ErrPersonalOrgLocked ErrorCode = "personal_org_locked"

	// ErrPersonalOrgLookupFailed is the personal_org_lookup_failed AuthKit HTTP wire error code.
	ErrPersonalOrgLookupFailed ErrorCode = "personal_org_lookup_failed"

	// ErrPhoneTwoFAUnavailable is the phone_2fa_unavailable AuthKit HTTP wire error code.
	ErrPhoneTwoFAUnavailable ErrorCode = "phone_2fa_unavailable"

	// ErrPhoneAlreadyVerified is the phone_already_verified AuthKit HTTP wire error code.
	ErrPhoneAlreadyVerified ErrorCode = "phone_already_verified"

	// ErrPhoneAndCodeRequired is the phone_and_code_required AuthKit HTTP wire error code.
	ErrPhoneAndCodeRequired ErrorCode = "phone_and_code_required"

	// ErrPhoneChangeUnavailable is the phone_change_unavailable AuthKit HTTP wire error code.
	ErrPhoneChangeUnavailable ErrorCode = "phone_change_unavailable"

	// ErrPhoneInUse is the phone_in_use AuthKit HTTP wire error code.
	ErrPhoneInUse ErrorCode = "phone_in_use"

	// ErrPhoneNotVerified is the phone_not_verified AuthKit HTTP wire error code.
	ErrPhoneNotVerified ErrorCode = "phone_not_verified"

	// ErrPhoneNumberMustBeE164 is the phone_number_must_be_e164 AuthKit HTTP wire error code.
	ErrPhoneNumberMustBeE164 ErrorCode = "phone_number_must_be_e164"

	// ErrPhoneRegistrationUnavailable is the phone_registration_unavailable AuthKit HTTP wire error code.
	ErrPhoneRegistrationUnavailable ErrorCode = "phone_registration_unavailable"

	// ErrPhoneUnavailable is the phone_unavailable AuthKit HTTP wire error code.
	ErrPhoneUnavailable ErrorCode = "phone_unavailable"

	// ErrPhoneUnchanged is the phone_unchanged AuthKit HTTP wire error code.
	ErrPhoneUnchanged ErrorCode = "phone_unchanged"

	// ErrPhoneVerificationFailed is the phone_verification_failed AuthKit HTTP wire error code.
	ErrPhoneVerificationFailed ErrorCode = "phone_verification_failed"

	// ErrPhoneVerificationUnavailable is the phone_verification_unavailable AuthKit HTTP wire error code.
	ErrPhoneVerificationUnavailable ErrorCode = "phone_verification_unavailable"

	// ErrPKCEGenerationFailed is the pkce_generation_failed AuthKit HTTP wire error code.
	ErrPKCEGenerationFailed ErrorCode = "pkce_generation_failed"

	// ErrPlatformPermissionLookupFailed is the platform_permission_lookup_failed AuthKit HTTP wire error code.
	ErrPlatformPermissionLookupFailed ErrorCode = "platform_permission_lookup_failed"

	// ErrPlatformPermissionsLookupFailed is the platform_permissions_lookup_failed AuthKit HTTP wire error code.
	ErrPlatformPermissionsLookupFailed ErrorCode = "platform_permissions_lookup_failed"

	// ErrPlatformRoleDefineFailed is the platform_role_define_failed AuthKit HTTP wire error code.
	ErrPlatformRoleDefineFailed ErrorCode = "platform_role_define_failed"

	// ErrPlatformRoleDeleteFailed is the platform_role_delete_failed AuthKit HTTP wire error code.
	ErrPlatformRoleDeleteFailed ErrorCode = "platform_role_delete_failed"

	// ErrPlatformRoleLookupFailed is the platform_role_lookup_failed AuthKit HTTP wire error code.
	ErrPlatformRoleLookupFailed ErrorCode = "platform_role_lookup_failed"

	// ErrPlatformRoleMembersFailed is the platform_role_members_failed AuthKit HTTP wire error code.
	ErrPlatformRoleMembersFailed ErrorCode = "platform_role_members_failed"

	// ErrPlatformRoleSetPermsFailed is the platform_role_set_perms_failed AuthKit HTTP wire error code.
	ErrPlatformRoleSetPermsFailed ErrorCode = "platform_role_set_perms_failed"

	// ErrPlatformRolesListFailed is the platform_roles_list_failed AuthKit HTTP wire error code.
	ErrPlatformRolesListFailed ErrorCode = "platform_roles_list_failed"

	// ErrPreferredLocaleLookupFailed is the preferred_locale_lookup_failed AuthKit HTTP wire error code.
	ErrPreferredLocaleLookupFailed ErrorCode = "preferred_locale_lookup_failed"

	// ErrProtectedRole is the protected_role AuthKit HTTP wire error code.
	ErrProtectedRole ErrorCode = "protected_role"

	// ErrProviderAlreadyLinked is the provider_already_linked AuthKit HTTP wire error code.
	ErrProviderAlreadyLinked ErrorCode = "provider_already_linked"

	// ErrProviderLinkFailed is the provider_link_failed AuthKit HTTP wire error code.
	ErrProviderLinkFailed ErrorCode = "provider_link_failed"

	// ErrProviderNotLinked is the provider_not_linked AuthKit HTTP wire error code.
	ErrProviderNotLinked ErrorCode = "provider_not_linked"

	// ErrRateLimited is the rate_limited AuthKit HTTP wire error code.
	ErrRateLimited ErrorCode = "rate_limited"

	// ErrReauthFailed is the reauth_failed AuthKit HTTP wire error code.
	ErrReauthFailed ErrorCode = "reauth_failed"

	// ErrReauthRequired is the reauth_required AuthKit HTTP wire error code.
	ErrReauthRequired ErrorCode = "reauth_required"

	// ErrRegenerateCodesFailed is the regenerate_codes_failed AuthKit HTTP wire error code.
	ErrRegenerateCodesFailed ErrorCode = "regenerate_codes_failed"

	// ErrRegistrationDisabled is the registration_disabled AuthKit HTTP wire error code.
	ErrRegistrationDisabled ErrorCode = "registration_disabled"

	// ErrRegistrationFailed is the registration_failed AuthKit HTTP wire error code.
	ErrRegistrationFailed ErrorCode = "registration_failed"

	// ErrRemoteApplicationDeleteFailed is the remote_application_delete_failed AuthKit HTTP wire error code.
	ErrRemoteApplicationDeleteFailed ErrorCode = "remote_application_delete_failed"

	// ErrRemoteApplicationLookupFailed is the remote_application_lookup_failed AuthKit HTTP wire error code.
	ErrRemoteApplicationLookupFailed ErrorCode = "remote_application_lookup_failed"

	// ErrRemoteApplicationMembershipFailed is the remote_application_membership_failed AuthKit HTTP wire error code.
	ErrRemoteApplicationMembershipFailed ErrorCode = "remote_application_membership_failed"

	// ErrRemoteApplicationNotFound is the remote_application_not_found AuthKit HTTP wire error code.
	ErrRemoteApplicationNotFound ErrorCode = "remote_application_not_found"

	// ErrRemoteApplicationOwnerLookupFailed is the remote_application_owner_lookup_failed AuthKit HTTP wire error code.
	ErrRemoteApplicationOwnerLookupFailed ErrorCode = "remote_application_owner_lookup_failed"

	// ErrRemoteApplicationRegisterFailed is the remote_application_register_failed AuthKit HTTP wire error code.
	ErrRemoteApplicationRegisterFailed ErrorCode = "remote_application_register_failed"

	// ErrRemoveMemberFailed is the remove_member_failed AuthKit HTTP wire error code.
	ErrRemoveMemberFailed ErrorCode = "remove_member_failed"

	// ErrRenameRateLimited is the rename_rate_limited AuthKit HTTP wire error code.
	ErrRenameRateLimited ErrorCode = core.ErrCodeRenameRateLimited

	// ErrResendFailed is the resend_failed AuthKit HTTP wire error code.
	ErrResendFailed ErrorCode = "resend_failed"

	// ErrReservedAccountNotFound is the reserved_account_not_found AuthKit HTTP wire error code.
	ErrReservedAccountNotFound ErrorCode = "reserved_account_not_found"

	// ErrResourceScopeDenied is the resource_scope_denied AuthKit HTTP wire error code.
	ErrResourceScopeDenied ErrorCode = "resource_scope_denied"

	// ErrRevokePlatformRoleFailed is the revoke_platform_role_failed AuthKit HTTP wire error code.
	ErrRevokePlatformRoleFailed ErrorCode = "revoke_platform_role_failed"

	// ErrRoleExceedsGrantor is the role_exceeds_grantor AuthKit HTTP wire error code.
	ErrRoleExceedsGrantor ErrorCode = "role_exceeds_grantor"

	// ErrRoleNotFound is the role_not_found AuthKit HTTP wire error code.
	ErrRoleNotFound ErrorCode = "role_not_found"

	// ErrRoleNotGrantableToAPIKey is the role_not_grantable_to_api_key AuthKit HTTP wire error code.
	ErrRoleNotGrantableToAPIKey ErrorCode = "role_not_grantable_to_api_key"

	// ErrRolePermissionsLookupFailed is the role_permissions_lookup_failed AuthKit HTTP wire error code.
	ErrRolePermissionsLookupFailed ErrorCode = "role_permissions_lookup_failed"

	// ErrRolePermissionsUpdateFailed is the role_permissions_update_failed AuthKit HTTP wire error code.
	ErrRolePermissionsUpdateFailed ErrorCode = "role_permissions_update_failed"

	// ErrSendCodeFailed is the send_code_failed AuthKit HTTP wire error code.
	ErrSendCodeFailed ErrorCode = "send_code_failed"

	// ErrSessionCreationFailed is the session_creation_failed AuthKit HTTP wire error code.
	ErrSessionCreationFailed ErrorCode = "session_creation_failed"

	// ErrSessionIssueFailed is the session_issue_failed AuthKit HTTP wire error code.
	ErrSessionIssueFailed ErrorCode = "session_issue_failed"

	// ErrSMSDeliveryFailed is the sms_delivery_failed AuthKit HTTP wire error code.
	ErrSMSDeliveryFailed ErrorCode = "sms_delivery_failed"

	// ErrSMSUnavailable is the sms_unavailable AuthKit HTTP wire error code.
	ErrSMSUnavailable ErrorCode = "sms_unavailable"

	// ErrStateStoreFailed is the state_store_failed AuthKit HTTP wire error code.
	ErrStateStoreFailed ErrorCode = "state_store_failed"

	// ErrTokenCreationFailed is the token_creation_failed AuthKit HTTP wire error code.
	ErrTokenCreationFailed ErrorCode = "token_creation_failed"

	// ErrTokenIssueFailed is the token_issue_failed AuthKit HTTP wire error code.
	ErrTokenIssueFailed ErrorCode = "token_issue_failed"

	// ErrUnassignRoleFailed is the unassign_role_failed AuthKit HTTP wire error code.
	ErrUnassignRoleFailed ErrorCode = "unassign_role_failed"

	// ErrUnauthorized is the unauthorized AuthKit HTTP wire error code.
	ErrUnauthorized ErrorCode = "unauthorized"

	// ErrUnknownPermission is the unknown_permission AuthKit HTTP wire error code.
	ErrUnknownPermission ErrorCode = "unknown_permission"

	// ErrUnknownProvider is the unknown_provider AuthKit HTTP wire error code.
	ErrUnknownProvider ErrorCode = "unknown_provider"

	// ErrUnknownRole is the unknown_role AuthKit HTTP wire error code.
	ErrUnknownRole ErrorCode = "unknown_role"

	// ErrUserBanned is the user_banned AuthKit HTTP wire error code.
	ErrUserBanned ErrorCode = "user_banned"

	// ErrUserCreationFailed is the user_creation_failed AuthKit HTTP wire error code.
	ErrUserCreationFailed ErrorCode = "user_creation_failed"

	// ErrUserInvitesLookupFailed is the user_invites_lookup_failed AuthKit HTTP wire error code.
	ErrUserInvitesLookupFailed ErrorCode = "user_invites_lookup_failed"

	// ErrUserLookupFailed is the user_lookup_failed AuthKit HTTP wire error code.
	ErrUserLookupFailed ErrorCode = "user_lookup_failed"

	// ErrUserNotFound is the user_not_found AuthKit HTTP wire error code.
	ErrUserNotFound ErrorCode = "user_not_found"

	// ErrUserinfoFailed is the userinfo_failed AuthKit HTTP wire error code.
	ErrUserinfoFailed ErrorCode = "userinfo_failed"

	// ErrUsernameCannotContainAt is the username_cannot_contain_at AuthKit HTTP wire error code.
	ErrUsernameCannotContainAt ErrorCode = core.ErrCodeUsernameCannotContainAt

	// ErrUsernameCannotStartWithPlus is the username_cannot_start_with_plus AuthKit HTTP wire error code.
	ErrUsernameCannotStartWithPlus ErrorCode = core.ErrCodeUsernameCannotStartWithPlus

	// ErrUsernameInUse is the username_in_use AuthKit HTTP wire error code.
	ErrUsernameInUse ErrorCode = "username_in_use"

	// ErrUsernameInvalidCharacters is the username_invalid_characters AuthKit HTTP wire error code.
	ErrUsernameInvalidCharacters ErrorCode = core.ErrCodeUsernameInvalidCharacters

	// ErrUsernameMissing is the username_missing AuthKit HTTP wire error code.
	ErrUsernameMissing ErrorCode = "username_missing"

	// ErrUsernameMustStartWithLetter is the username_must_start_with_letter AuthKit HTTP wire error code.
	ErrUsernameMustStartWithLetter ErrorCode = core.ErrCodeUsernameMustStartWithLetter

	// ErrUsernameNotAllowed is the username_not_allowed AuthKit HTTP wire error code.
	ErrUsernameNotAllowed ErrorCode = core.ErrCodeUsernameNotAllowed

	// ErrUsernameTooLong is the username_too_long AuthKit HTTP wire error code.
	ErrUsernameTooLong ErrorCode = core.ErrCodeUsernameTooLong

	// ErrUsernameTooShort is the username_too_short AuthKit HTTP wire error code.
	ErrUsernameTooShort ErrorCode = core.ErrCodeUsernameTooShort

	// ErrVerificationLinkExpired is the verification_link_expired AuthKit HTTP wire error code.
	ErrVerificationLinkExpired ErrorCode = "verification_link_expired"

	// ErrVerificationRequestFailed is the verification_request_failed AuthKit HTTP wire error code.
	ErrVerificationRequestFailed ErrorCode = "verification_request_failed"

	// ErrWalletAlreadyLinked is the wallet_already_linked AuthKit HTTP wire error code.
	ErrWalletAlreadyLinked ErrorCode = "wallet_already_linked"
)
