package authhttp

import "github.com/open-rails/authkit/embedded"

// ErrorCode is a stable AuthKit HTTP wire error code.
type ErrorCode string

// String returns the wire value.
func (c ErrorCode) String() string { return string(c) }

const (
	ErrRenamesDisabled      ErrorCode = "renames_disabled"
	ErrNameAdmissionRefused ErrorCode = "name_admission_refused"
	// ErrTwoFAFactorExists rejects enrollment when the permitted factor slot is occupied.
	ErrTwoFAFactorExists ErrorCode = "2fa_factor_exists"

	// ErrTwoFAChallengeFailed is the 2fa_challenge_failed AuthKit HTTP wire error code.
	ErrTwoFAChallengeFailed ErrorCode = "2fa_challenge_failed"

	// ErrTwoFASendFailed is the 2fa_send_failed AuthKit HTTP wire error code.
	ErrTwoFASendFailed ErrorCode = "2fa_send_failed"

	// ErrTwoFAEnrollmentRequired is the 2fa_enrollment_required AuthKit HTTP wire error code.
	ErrTwoFAEnrollmentRequired ErrorCode = "2fa_enrollment_required"

	// ErrAbandonFailed is the abandon_failed AuthKit HTTP wire error code.
	ErrAbandonFailed ErrorCode = "abandon_failed"

	// ErrAccessTokenCreateFailed is the access_token_create_failed AuthKit HTTP wire error code.
	ErrAccessTokenCreateFailed ErrorCode = "access_token_create_failed"

	// ErrAccountExistsLinkRequired is the account_exists_link_required AuthKit HTTP wire error code.
	ErrAccountExistsLinkRequired ErrorCode = "account_exists_link_required"

	// ErrAddressMismatch is the address_mismatch AuthKit HTTP wire error code.
	ErrAddressMismatch ErrorCode = "address_mismatch"

	// ErrAddressRequired is the address_required AuthKit HTTP wire error code.
	ErrAddressRequired ErrorCode = "address_required"

	// ErrApplicationDocumentFetchFailed is the application_document_fetch_failed AuthKit HTTP wire error code.
	ErrApplicationDocumentFetchFailed ErrorCode = "application_document_fetch_failed"

	// ErrApplicationDocumentInvalid is the application_document_invalid AuthKit HTTP wire error code.
	ErrApplicationDocumentInvalid ErrorCode = "application_document_invalid"

	// ErrApplicationDomainConflict is the application_domain_conflict AuthKit HTTP wire error code.
	ErrApplicationDomainConflict ErrorCode = "application_domain_conflict"

	// ErrApplicationDomainInvalid is the application_domain_invalid AuthKit HTTP wire error code.
	ErrApplicationDomainInvalid ErrorCode = "application_domain_invalid"

	// ErrApplicationIssuerConflict is the application_issuer_conflict AuthKit HTTP wire error code.
	ErrApplicationIssuerConflict ErrorCode = "application_issuer_conflict"

	// ErrApplicationNotDomainRooted is the application_not_domain_rooted AuthKit HTTP wire error code.
	ErrApplicationNotDomainRooted ErrorCode = "application_not_domain_rooted"

	// ErrApplicationRegistrationDisabled is the application_registration_disabled AuthKit HTTP wire error code.
	ErrApplicationRegistrationDisabled ErrorCode = "application_registration_disabled"

	// ErrApplicationSignatureInvalid is the application_signature_invalid AuthKit HTTP wire error code.
	ErrApplicationSignatureInvalid ErrorCode = "application_signature_invalid"

	// ErrApplicationSignatureStale is the application_signature_stale AuthKit HTTP wire error code.
	ErrApplicationSignatureStale ErrorCode = "application_signature_stale"

	// ErrApplicationSlugConflict is the application_slug_conflict AuthKit HTTP wire error code.
	ErrApplicationSlugConflict ErrorCode = "application_slug_conflict"

	// ErrApplicationTierInvalid is the application_tier_invalid AuthKit HTTP wire error code.
	ErrApplicationTierInvalid ErrorCode = "application_tier_invalid"

	// ErrAuthRequiredForLink is the auth_required_for_link AuthKit HTTP wire error code.
	ErrAuthRequiredForLink ErrorCode = "auth_required_for_link"

	// ErrAuthenticationFailed is the authentication_failed AuthKit HTTP wire error code.
	ErrAuthenticationFailed ErrorCode = "authentication_failed"

	// ErrAuthenticationRequired is the authentication_required AuthKit HTTP wire error code.
	ErrAuthenticationRequired ErrorCode = "authentication_required"

	// ErrCannotRemoveLastOwner is the cannot_remove_last_owner AuthKit HTTP wire error code.
	ErrCannotRemoveLastOwner ErrorCode = "cannot_remove_last_owner"

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

	// ErrDelegatedDocumentUnavailable is the delegated_document_unavailable AuthKit HTTP wire error code.
	ErrDelegatedDocumentUnavailable ErrorCode = "delegated_document_unavailable"

	// ErrDelegatedMintFailed is the delegated_mint_failed AuthKit HTTP wire error code.
	ErrDelegatedMintFailed ErrorCode = "delegated_mint_failed"

	// ErrDelegatedTokenTooLarge is the delegated_token_too_large AuthKit HTTP wire error code.
	ErrDelegatedTokenTooLarge ErrorCode = "delegated_token_too_large"

	// ErrDelegationAuthorizerUnavailable is the delegation_authorizer_unavailable AuthKit HTTP wire error code.
	ErrDelegationAuthorizerUnavailable ErrorCode = "delegation_authorizer_unavailable"

	// ErrDelegationRefused is the delegation_refused AuthKit HTTP wire error code.
	ErrDelegationRefused ErrorCode = "delegation_refused"

	// ErrDisableTwoFAFailed is the disable_2fa_failed AuthKit HTTP wire error code.
	ErrDisableTwoFAFailed ErrorCode = "disable_2fa_failed"

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

	// ErrFailedToRevoke is the failed_to_revoke AuthKit HTTP wire error code.
	ErrFailedToRevoke ErrorCode = "failed_to_revoke"

	// ErrFailedToRevokeAll is the failed_to_revoke_all AuthKit HTTP wire error code.
	ErrFailedToRevokeAll ErrorCode = "failed_to_revoke_all"

	// ErrFailedToRevokeSessions is the failed_to_revoke_sessions AuthKit HTTP wire error code.
	ErrFailedToRevokeSessions ErrorCode = "failed_to_revoke_sessions"

	// ErrFailedToUnban is the failed_to_unban AuthKit HTTP wire error code.
	ErrFailedToUnban ErrorCode = "failed_to_unban"

	// ErrFailedToUnlink is the failed_to_unlink AuthKit HTTP wire error code.
	ErrFailedToUnlink ErrorCode = "failed_to_unlink"

	// ErrFailedToUpdatePreferredLanguage is the failed_to_update_preferred_language AuthKit HTTP wire error code.
	ErrFailedToUpdatePreferredLanguage ErrorCode = "failed_to_update_preferred_language"

	// ErrFailedToUpdateUsername is the failed_to_update_username AuthKit HTTP wire error code.
	ErrFailedToUpdateUsername ErrorCode = "failed_to_update_username"

	// ErrForbidden is the forbidden AuthKit HTTP wire error code.
	ErrForbidden ErrorCode = "forbidden"
	// ErrAccountAuthorityEscalation is the account_authority_escalation AuthKit HTTP wire error code.
	ErrAccountAuthorityEscalation ErrorCode = "account_authority_escalation"

	// ErrGroupCreationRefused is the group_creation_refused AuthKit HTTP wire error code.
	ErrGroupCreationRefused ErrorCode = "group_creation_refused"

	// ErrGroupSlugApplicationManaged is the group_slug_application_managed AuthKit HTTP wire error code.
	ErrGroupSlugApplicationManaged ErrorCode = "group_slug_application_managed"

	// ErrGroupSlugInvalid is the group_slug_invalid AuthKit HTTP wire error code.
	ErrGroupSlugInvalid ErrorCode = "group_slug_invalid"

	// ErrGroupSlugReserved is the group_slug_reserved AuthKit HTTP wire error code.
	ErrGroupSlugReserved ErrorCode = "group_slug_reserved"

	// ErrGroupSlugTaken is the group_slug_taken AuthKit HTTP wire error code.
	ErrGroupSlugTaken ErrorCode = "group_slug_taken"

	// ErrHashFailed is the hash_failed AuthKit HTTP wire error code.
	ErrHashFailed ErrorCode = "hash_failed"

	// ErrInvalidAddress is the invalid_address AuthKit HTTP wire error code.
	ErrInvalidAddress ErrorCode = "invalid_address"

	// ErrInvalidBaseURL is the invalid_base_url AuthKit HTTP wire error code.
	ErrInvalidBaseURL ErrorCode = "invalid_base_url"

	// ErrInvalidAudiences is the invalid_audiences AuthKit HTTP wire error code.
	ErrInvalidAudiences ErrorCode = "invalid_audiences"

	// ErrInvalidDelegateCertificate is the invalid_delegate_certificate AuthKit HTTP wire error code.
	ErrInvalidDelegateCertificate ErrorCode = "invalid_delegate_certificate"

	// ErrInvalidRequestedGrant is the invalid_requested_grant AuthKit HTTP wire error code.
	ErrInvalidRequestedGrant ErrorCode = "invalid_requested_grant"

	// ErrTTLExceedsDelegateCertificate is the ttl_exceeds_delegate_certificate AuthKit HTTP wire error code.
	ErrTTLExceedsDelegateCertificate ErrorCode = "ttl_exceeds_delegate_certificate"

	// ErrInvalidChallenge is the invalid_challenge AuthKit HTTP wire error code.
	ErrInvalidChallenge ErrorCode = "invalid_challenge"

	// ErrInvalidCode is the invalid_code AuthKit HTTP wire error code.
	ErrInvalidCode ErrorCode = "invalid_code"

	// ErrInvalidCredentials is the invalid_credentials AuthKit HTTP wire error code.
	ErrInvalidCredentials ErrorCode = "invalid_credentials"

	// ErrInvalidEmail is the invalid_email AuthKit HTTP wire error code.
	ErrInvalidEmail ErrorCode = embedded.ErrCodeInvalidEmail

	// ErrInvalidExpiry is the invalid_expiry AuthKit HTTP wire error code.
	ErrInvalidExpiry ErrorCode = "invalid_expiry"

	// ErrInvalidIdentifier is the invalid_identifier AuthKit HTTP wire error code.
	ErrInvalidIdentifier ErrorCode = "invalid_identifier"

	// ErrInvalidMessageEncoding is the invalid_message_encoding AuthKit HTTP wire error code.
	ErrInvalidMessageEncoding ErrorCode = "invalid_message_encoding"

	// ErrInvalidMethod is the invalid_method AuthKit HTTP wire error code.
	ErrInvalidMethod ErrorCode = "invalid_method"

	// ErrInvalidOrExpiredCode is the invalid_or_expired_code AuthKit HTTP wire error code.
	ErrInvalidOrExpiredCode ErrorCode = "invalid_or_expired_code"

	// ErrInvalidOrExpiredToken is the invalid_or_expired_token AuthKit HTTP wire error code.
	ErrInvalidOrExpiredToken ErrorCode = "invalid_or_expired_token"

	// ErrInvalidPassword is the invalid_password AuthKit HTTP wire error code.
	ErrInvalidPassword ErrorCode = "invalid_password"

	// ErrInvalidPhoneNumber is the invalid_phone_number AuthKit HTTP wire error code.
	ErrInvalidPhoneNumber ErrorCode = embedded.ErrCodeInvalidPhoneNumber

	// ErrInvalidPreferredLanguage is the invalid_preferred_language AuthKit HTTP wire error code.
	ErrInvalidPreferredLanguage ErrorCode = "invalid_preferred_language"

	// ErrInvalidProvider is the invalid_provider AuthKit HTTP wire error code.
	ErrInvalidProvider ErrorCode = "invalid_provider"

	// ErrInvalidRefreshToken is the invalid_refresh_token AuthKit HTTP wire error code.
	ErrInvalidRefreshToken ErrorCode = "invalid_refresh_token"

	// ErrInvalidRequest is the invalid_request AuthKit HTTP wire error code.
	ErrInvalidRequest ErrorCode = "invalid_request"

	// ErrInvalidRole is the invalid_role AuthKit HTTP wire error code.
	ErrInvalidRole ErrorCode = "invalid_role"

	// ErrInvalidSignature is the invalid_signature AuthKit HTTP wire error code.
	ErrInvalidSignature ErrorCode = "invalid_signature"

	// ErrInvalidSignatureEncoding is the invalid_signature_encoding AuthKit HTTP wire error code.
	ErrInvalidSignatureEncoding ErrorCode = "invalid_signature_encoding"

	// ErrInvalidState is the invalid_state AuthKit HTTP wire error code.
	ErrInvalidState ErrorCode = "invalid_state"

	// ErrInvalidUI is the invalid_ui AuthKit HTTP wire error code.
	ErrInvalidUI ErrorCode = "invalid_ui"

	// ErrInvalidUntil is the invalid_until AuthKit HTTP wire error code.
	ErrInvalidUntil ErrorCode = "invalid_until"

	// ErrLinkFailed is the link_failed AuthKit HTTP wire error code.
	ErrLinkFailed ErrorCode = "link_failed"

	// ErrMissingFields is the missing_fields AuthKit HTTP wire error code.
	ErrMissingFields ErrorCode = "missing_fields"

	// ErrMissingName is the missing_name AuthKit HTTP wire error code.
	ErrMissingName ErrorCode = "missing_name"

	// ErrMissingSessionID is the missing_session_id AuthKit HTTP wire error code.
	ErrMissingSessionID ErrorCode = "missing_session_id"

	// ErrMissingSidClaim is the missing_sid_claim AuthKit HTTP wire error code.
	ErrMissingSidClaim ErrorCode = "missing_sid_claim"

	// ErrNotAuthenticated is the not_authenticated AuthKit HTTP wire error code.
	ErrNotAuthenticated ErrorCode = "not_authenticated"

	// ErrNotFound is the not_found AuthKit HTTP wire error code.
	ErrNotFound ErrorCode = "not_found"

	// ErrOIDCBeginFailed is the oidc_begin_failed AuthKit HTTP wire error code.
	ErrOIDCBeginFailed ErrorCode = "oidc_begin_failed"

	// ErrOIDCExchangeFailed is the oidc_exchange_failed AuthKit HTTP wire error code.
	ErrOIDCExchangeFailed ErrorCode = "oidc_exchange_failed"

	// ErrOwnerSlugTaken is the owner_slug_taken AuthKit HTTP wire error code.
	ErrOwnerSlugTaken ErrorCode = embedded.ErrCodeOwnerSlugTaken

	// ErrPasswordChangeFailed is the password_change_failed AuthKit HTTP wire error code.
	ErrPasswordChangeFailed ErrorCode = "password_change_failed"

	// ErrPasswordResetRequestFailed is the password_reset_request_failed AuthKit HTTP wire error code.
	ErrPasswordResetRequestFailed ErrorCode = "password_reset_request_failed"

	// ErrPasswordResetRequired is the password_reset_required AuthKit HTTP wire error code.
	ErrPasswordResetRequired ErrorCode = "password_reset_required"

	// ErrPasskeyFailed is the passkey_failed AuthKit HTTP wire error code.
	ErrPasskeyFailed ErrorCode = "passkey_failed"

	// ErrPasswordTooShort is the password_too_short AuthKit HTTP wire error code.
	ErrPasswordTooShort ErrorCode = embedded.ErrCodePasswordTooShort

	// ErrPendingRegistrationNotFound is the pending_registration_not_found AuthKit HTTP wire error code.
	ErrPendingRegistrationNotFound ErrorCode = "pending_registration_not_found"

	// ErrPhoneTwoFAUnavailable is the phone_2fa_unavailable AuthKit HTTP wire error code.
	ErrPhoneTwoFAUnavailable ErrorCode = "phone_2fa_unavailable"

	// ErrPhoneAlreadyVerified is the phone_already_verified AuthKit HTTP wire error code.
	ErrPhoneAlreadyVerified ErrorCode = "phone_already_verified"

	// ErrPhoneAndCodeRequired is the phone_and_code_required AuthKit HTTP wire error code.
	ErrPhoneAndCodeRequired ErrorCode = "phone_and_code_required"

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

	// ErrPasswordlessDisabled is the passwordless_disabled AuthKit HTTP wire error code.
	ErrPasswordlessDisabled ErrorCode = "passwordless_disabled"
	// ErrDeviceKeysDisabled is the device_keys_disabled AuthKit HTTP wire error code.
	ErrDeviceKeysDisabled ErrorCode = "device_keys_disabled"

	// ErrPKCEGenerationFailed is the pkce_generation_failed AuthKit HTTP wire error code.
	ErrPKCEGenerationFailed ErrorCode = "pkce_generation_failed"

	// ErrPreferredLanguageLookupFailed is the preferred_language_lookup_failed AuthKit HTTP wire error code.
	ErrPreferredLanguageLookupFailed ErrorCode = "preferred_language_lookup_failed"

	// ErrProviderAlreadyLinked is the provider_already_linked AuthKit HTTP wire error code.
	ErrProviderAlreadyLinked ErrorCode = "provider_already_linked"
	// ErrProviderChangeRequiresUnlink requires explicit unlink before changing provider identity.
	ErrProviderChangeRequiresUnlink ErrorCode = "provider_change_requires_unlink"

	// ErrProviderError is the provider_error AuthKit HTTP wire error code: an
	// IdP reported a callback ?error= value that is not a clean token
	// (sanitizeProviderErrorCode), so the raw value is not reflected.
	ErrProviderError ErrorCode = "provider_error"

	// ErrProviderLinkFailed is the provider_link_failed AuthKit HTTP wire error code.
	ErrProviderLinkFailed ErrorCode = "provider_link_failed"

	// ErrProviderNotLinked is the provider_not_linked AuthKit HTTP wire error code.
	ErrProviderNotLinked ErrorCode = "provider_not_linked"

	// ErrRateLimited is the rate_limited AuthKit HTTP wire error code.
	ErrRateLimited ErrorCode = "rate_limited"

	// ErrStepUpFailed is the step_up_failed AuthKit HTTP wire error code.
	ErrStepUpFailed ErrorCode = "step_up_failed"

	// ErrStepUpRequired is the step_up_required AuthKit HTTP wire error code: the
	// caller must re-prove identity (any configured method) before this action.
	ErrStepUpRequired ErrorCode = "step_up_required"

	// ErrRegenerateCodesFailed is the regenerate_codes_failed AuthKit HTTP wire error code.
	ErrRegenerateCodesFailed ErrorCode = "regenerate_codes_failed"

	// ErrRegistrationDisabled is the registration_disabled AuthKit HTTP wire error code.
	ErrRegistrationDisabled ErrorCode = "registration_disabled"

	// ErrRegistrationFailed is the registration_failed AuthKit HTTP wire error code.
	ErrRegistrationFailed ErrorCode = "registration_failed"

	// ErrRemoteApplicationIssuerConflict indicates an issuer controlled by another group.
	ErrRemoteApplicationIssuerConflict ErrorCode = "remote_application_issuer_conflict"

	// ErrRemoteApplicationNotFound is the remote_application_not_found AuthKit HTTP wire error code.
	ErrRemoteApplicationNotFound ErrorCode = "remote_application_not_found"

	// ErrRenameRateLimited is the rename_rate_limited AuthKit HTTP wire error code.
	ErrRenameRateLimited ErrorCode = embedded.ErrCodeRenameRateLimited

	// ErrResendFailed is the resend_failed AuthKit HTTP wire error code.
	ErrResendFailed ErrorCode = "resend_failed"

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

	// ErrTokenIssueFailed is the token_issue_failed AuthKit HTTP wire error code.
	ErrTokenIssueFailed ErrorCode = "token_issue_failed"

	// ErrUnauthorized is the unauthorized AuthKit HTTP wire error code.
	ErrUnauthorized ErrorCode = "unauthorized"

	// ErrUnknownProvider is the unknown_provider AuthKit HTTP wire error code.
	ErrUnknownProvider ErrorCode = "unknown_provider"

	// ErrUnknownRole is the unknown_role AuthKit HTTP wire error code.
	ErrUnknownRole ErrorCode = "unknown_role"

	// ErrUserBanned is the user_banned AuthKit HTTP wire error code.
	ErrUserBanned ErrorCode = "user_banned"

	// ErrUserCreationFailed is the user_creation_failed AuthKit HTTP wire error code.
	ErrUserCreationFailed ErrorCode = "user_creation_failed"

	// ErrUserLookupFailed is the user_lookup_failed AuthKit HTTP wire error code.
	ErrUserLookupFailed ErrorCode = "user_lookup_failed"

	// ErrUserNotFound is the user_not_found AuthKit HTTP wire error code.
	ErrUserNotFound ErrorCode = "user_not_found"

	// ErrUserinfoFailed is the userinfo_failed AuthKit HTTP wire error code.
	ErrUserinfoFailed ErrorCode = "userinfo_failed"

	// ErrUsernameCannotContainAt is the username_cannot_contain_at AuthKit HTTP wire error code.
	ErrUsernameCannotContainAt ErrorCode = embedded.ErrCodeUsernameCannotContainAt

	// ErrUsernameCannotStartWithPlus is the username_cannot_start_with_plus AuthKit HTTP wire error code.
	ErrUsernameCannotStartWithPlus ErrorCode = embedded.ErrCodeUsernameCannotStartWithPlus

	// ErrUsernameInUse is the username_in_use AuthKit HTTP wire error code.
	ErrUsernameInUse ErrorCode = "username_in_use"

	// ErrUsernameInvalidCharacters is the username_invalid_characters AuthKit HTTP wire error code.
	ErrUsernameInvalidCharacters ErrorCode = embedded.ErrCodeUsernameInvalidCharacters

	// ErrUsernameMustStartWithLetter is the username_must_start_with_letter AuthKit HTTP wire error code.
	ErrUsernameMustStartWithLetter ErrorCode = embedded.ErrCodeUsernameMustStartWithLetter

	// ErrUsernameNotAllowed is the username_not_allowed AuthKit HTTP wire error code.
	ErrUsernameNotAllowed ErrorCode = embedded.ErrCodeUsernameNotAllowed

	// ErrUsernameTooLong is the username_too_long AuthKit HTTP wire error code.
	ErrUsernameTooLong ErrorCode = embedded.ErrCodeUsernameTooLong

	// ErrUsernameTooShort is the username_too_short AuthKit HTTP wire error code.
	ErrUsernameTooShort ErrorCode = embedded.ErrCodeUsernameTooShort

	// ErrVerificationLinkExpired is the verification_link_expired AuthKit HTTP wire error code.
	ErrVerificationLinkExpired ErrorCode = "verification_link_expired"

	// ErrVerificationRequestFailed is the verification_request_failed AuthKit HTTP wire error code.
	ErrVerificationRequestFailed ErrorCode = "verification_request_failed"

	// ErrWalletAlreadyLinked is the wallet_already_linked AuthKit HTTP wire error code.
	ErrWalletAlreadyLinked ErrorCode = "wallet_already_linked"

	// ErrWalletChangeRequiresUnlink requires removing the current wallet before linking another.
	ErrWalletChangeRequiresUnlink ErrorCode = "wallet_change_requires_unlink"
)
