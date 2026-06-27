// Re-exports of the public types, constants, sentinel errors, and helper
// functions implemented in internal/authcore. This is the public alias layer:
// when authcore's exported surface changes, mirror the intended-public symbols
// here. The Service facade itself lives in facade.go / facade_methods.go.
package embedded

import authcore "github.com/open-rails/authkit/internal/authcore"

// Re-exported types.
// #130 bulk-import result types + status constants (hand-added; the generator
// also picks these up on a full regen).

type APIKeysConfig = authcore.APIKeysConfig
type AdminRecoverUserInput = authcore.AdminRecoverUserInput
type AuthSessionEvent = authcore.AuthSessionEvent
type BatchEntitlementsProvider = authcore.BatchEntitlementsProvider
type Config = authcore.Config
type CustomRoleResolver = authcore.CustomRoleResolver
type EmailSender = authcore.EmailSender
type EntitlementFilterProvider = authcore.EntitlementFilterProvider
type EntitlementsProvider = authcore.EntitlementsProvider
type EphemeralMode = authcore.EphemeralMode
type EphemeralStore = authcore.EphemeralStore
type FrontendConfig = authcore.FrontendConfig
type GeneratedRoute = authcore.GeneratedRoute
type GroupAssignment = authcore.GroupAssignment
type GroupSchema = authcore.GroupSchema
type PersonaDef = authcore.PersonaDef
type PersonaCapabilities = authcore.PersonaCapabilities
type IdentityConfig = authcore.IdentityConfig
type KeysConfig = authcore.KeysConfig
type Keyset = authcore.Keyset
type Option = authcore.Option
type Options = authcore.Options
type Passkey = authcore.Passkey
type PasskeyConfig = authcore.PasskeyConfig
type PasskeyLoginResult = authcore.PasskeyLoginResult
type PendingChangeKind = authcore.PendingChangeKind
type PendingRegistration = authcore.PendingRegistration
type PermissionGroupStore = authcore.PermissionGroupStore
type RegistrationConfig = authcore.RegistrationConfig
type RegistrationMode = authcore.RegistrationMode
type RegistrationVerificationPolicy = authcore.RegistrationVerificationPolicy
type RoleDef = authcore.RoleDef
type RemovedMFARoleAssignment = authcore.RemovedMFARoleAssignment
type SMSHealthChecker = authcore.SMSHealthChecker
type SMSSender = authcore.SMSSender
type SessionEventType = authcore.SessionEventType
type SessionFreshness = authcore.SessionFreshness
type SessionRevokeReason = authcore.SessionRevokeReason
type SolanaLinkedAccount = authcore.SolanaLinkedAccount
type TokenConfig = authcore.TokenConfig
type TwoFactorConfig = authcore.TwoFactorConfig
type TwoFactorFactor = authcore.TwoFactorFactor
type TwoFactorSettings = authcore.TwoFactorSettings
type ValidationError = authcore.ValidationError
type VerificationMessage = authcore.VerificationMessage

// Re-exported constants.
const AssuranceLevelMFA = authcore.AssuranceLevelMFA
const AssuranceLevelPassword = authcore.AssuranceLevelPassword
const DefaultBootstrapManifestPath = authcore.DefaultBootstrapManifestPath
const DelegatedAccessTokenType = authcore.DelegatedAccessTokenType
const EphemeralMemory = authcore.EphemeralMemory
const EphemeralRedis = authcore.EphemeralRedis
const ErrCodeInvalidEmail = authcore.ErrCodeInvalidEmail
const ErrCodeInvalidPhoneNumber = authcore.ErrCodeInvalidPhoneNumber
const ErrCodeOwnerSlugTaken = authcore.ErrCodeOwnerSlugTaken
const ErrCodePasswordTooShort = authcore.ErrCodePasswordTooShort
const ErrCodeRenameRateLimited = authcore.ErrCodeRenameRateLimited
const ErrCodeUsernameCannotContainAt = authcore.ErrCodeUsernameCannotContainAt
const ErrCodeUsernameCannotStartWithPlus = authcore.ErrCodeUsernameCannotStartWithPlus
const ErrCodeUsernameInvalidCharacters = authcore.ErrCodeUsernameInvalidCharacters
const ErrCodeUsernameMustStartWithLetter = authcore.ErrCodeUsernameMustStartWithLetter
const ErrCodeUsernameNotAllowed = authcore.ErrCodeUsernameNotAllowed
const ErrCodeUsernameTooLong = authcore.ErrCodeUsernameTooLong
const ErrCodeUsernameTooShort = authcore.ErrCodeUsernameTooShort
const HashAlgoLegacyResetRequired = authcore.HashAlgoLegacyResetRequired
const KindChangeEmail = authcore.KindChangeEmail
const KindChangePhone = authcore.KindChangePhone
const KindRegisterEmail = authcore.KindRegisterEmail
const KindRegisterPhone = authcore.KindRegisterPhone
const MaxCustomJWTLifetime = authcore.MaxCustomJWTLifetime
const OwnerRoleName = authcore.OwnerRoleName
const PasswordlessChannelEmail = authcore.PasswordlessChannelEmail
const PasswordlessChannelSMS = authcore.PasswordlessChannelSMS
const PasswordlessModeBoth = authcore.PasswordlessModeBoth
const PasswordlessModeCode = authcore.PasswordlessModeCode
const PasswordlessModeLink = authcore.PasswordlessModeLink
const PermRootCredentialsManage = authcore.PermRootCredentialsManage
const PermRootResourcesRead = authcore.PermRootResourcesRead
const PermRootRolesManage = authcore.PermRootRolesManage
const PermRootUsersBan = authcore.PermRootUsersBan
const PermRootUsersDelete = authcore.PermRootUsersDelete
const PermRootUsersRecover = authcore.PermRootUsersRecover
const RegistrationModeClosed = authcore.RegistrationModeClosed
const RegistrationModeInviteOnly = authcore.RegistrationModeInviteOnly
const RegistrationModeOpen = authcore.RegistrationModeOpen
const RegistrationVerificationNone = authcore.RegistrationVerificationNone
const RegistrationVerificationOptional = authcore.RegistrationVerificationOptional
const RegistrationVerificationRequired = authcore.RegistrationVerificationRequired
const RemoteApplicationAccessTokenType = authcore.RemoteApplicationAccessTokenType
const RootPersona = authcore.RootPersona
const SensitiveActionFreshAuthWindow = authcore.SensitiveActionFreshAuthWindow
const ServiceJWTType = authcore.ServiceJWTType
const SessionEventCreated = authcore.SessionEventCreated
const SessionEventFailed = authcore.SessionEventFailed
const SessionEventPasswordChange = authcore.SessionEventPasswordChange
const SessionEventPasswordRecovery = authcore.SessionEventPasswordRecovery
const SessionEventRevoked = authcore.SessionEventRevoked
const SessionRevokeReasonAdminRevoke = authcore.SessionRevokeReasonAdminRevoke
const SessionRevokeReasonAdminRevokeAll = authcore.SessionRevokeReasonAdminRevokeAll
const SessionRevokeReasonAdminSetPassword = authcore.SessionRevokeReasonAdminSetPassword
const SessionRevokeReasonBanned = authcore.SessionRevokeReasonBanned
const SessionRevokeReasonEvicted = authcore.SessionRevokeReasonEvicted
const SessionRevokeReasonLogout = authcore.SessionRevokeReasonLogout
const SessionRevokeReasonPasswordChange = authcore.SessionRevokeReasonPasswordChange
const SessionRevokeReasonRefreshReuseDetected = authcore.SessionRevokeReasonRefreshReuseDetected
const SessionRevokeReasonSoftDeleted = authcore.SessionRevokeReasonSoftDeleted
const SessionRevokeReasonUnknown = authcore.SessionRevokeReasonUnknown
const SessionRevokeReasonUserDisabled = authcore.SessionRevokeReasonUserDisabled
const SessionRevokeReasonUserRevoke = authcore.SessionRevokeReasonUserRevoke
const SessionRevokeReasonUserRevokeAll = authcore.SessionRevokeReasonUserRevokeAll
const SolanaProviderSlug = authcore.SolanaProviderSlug
const SolanaSNSStatusDisabled = authcore.SolanaSNSStatusDisabled
const SolanaSNSStatusError = authcore.SolanaSNSStatusError
const SolanaSNSStatusNotFound = authcore.SolanaSNSStatusNotFound
const SolanaSNSStatusPending = authcore.SolanaSNSStatusPending
const SolanaSNSStatusResolved = authcore.SolanaSNSStatusResolved
const SolanaSNSStatusStale = authcore.SolanaSNSStatusStale
const SubjectKindRemoteApp = authcore.SubjectKindRemoteApp
const SubjectKindUser = authcore.SubjectKindUser
const TwoFactorDisabled = authcore.TwoFactorDisabled
const TwoFactorOptional = authcore.TwoFactorOptional
const TwoFactorRequired = authcore.TwoFactorRequired
const TwoFactorEmail = authcore.TwoFactorEmail
const TwoFactorSMS = authcore.TwoFactorSMS
const TwoFactorTOTP = authcore.TwoFactorTOTP

// Re-exported variables, sentinel errors, and functions.
var BuildSchema = authcore.BuildSchema

// #136 no-escalation role-assignment errors.
var IntrinsicRootPermissions = authcore.IntrinsicRootPermissions
var IntrinsicRootPersona = authcore.IntrinsicRootPersona
var IsDevEnvironment = authcore.IsDevEnvironment
var LoadBootstrapManifestFile = authcore.LoadBootstrapManifestFile
var MintDelegatedAccessToken = authcore.MintDelegatedAccessToken
var MintRemoteApplicationAccessToken = authcore.MintRemoteApplicationAccessToken
var MintServiceJWT = authcore.MintServiceJWT
var NewGroupSchema = authcore.NewGroupSchema
var NewPermissionGroupStore = authcore.NewPermissionGroupStore
var NormalizeEmail = authcore.NormalizeEmail
var NormalizePhone = authcore.NormalizePhone
var NormalizePreferredLanguage = authcore.NormalizePreferredLanguage
var NormalizeRemoteAppTrustSource = authcore.NormalizeRemoteAppTrustSource
var OwnerGrant = authcore.OwnerGrant
var PermCredentialsManage = authcore.PermCredentialsManage
var PermCredentialsRead = authcore.PermCredentialsRead
var PermMembersManage = authcore.PermMembersManage
var PermMembersRead = authcore.PermMembersRead
var PermRolesManage = authcore.PermRolesManage
var PermRolesRead = authcore.PermRolesRead
var PermissionPersona = authcore.PermissionPersona
var ValidateEmail = authcore.ValidateEmail
var ValidateGrantPattern = authcore.ValidateGrantPattern
var ValidatePassword = authcore.ValidatePassword
var ValidatePermission = authcore.ValidatePermission
var ValidatePhone = authcore.ValidatePhone
var ValidateUsername = authcore.ValidateUsername
var ValidationErrorCode = authcore.ValidationErrorCode
var WithClickHouse = authcore.WithClickHouse
var WithEmailSender = authcore.WithEmailSender
var WithEntitlements = authcore.WithEntitlements
var WithPostgres = authcore.WithPostgres
var WithSMSSender = authcore.WithSMSSender
var WithSessionRevokeReason = authcore.WithSessionRevokeReason
