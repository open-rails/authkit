// Re-exports of the public types, constants, sentinel errors, and helper
// functions implemented in internal/authcore. This is the public alias layer:
// when authcore's exported surface changes, mirror the intended-public symbols
// here. The Service facade itself lives in facade.go / facade_methods.go.
package embedded

import authcore "github.com/open-rails/authkit/internal/authcore"

// Re-exported types. Every alias here is either referenced by name from a
// host or this repo's non-test code, or names a Config field / option
// parameter / host-implemented interface a host must be able to write down.

type APIKeysConfig = authcore.APIKeysConfig
type ApplicationsConfig = authcore.ApplicationsConfig
type Config = authcore.Config
type CustomRoleResolver = authcore.CustomRoleResolver
type DelegationAuthorizer = authcore.DelegationAuthorizer
type DelegationRequest = authcore.DelegationRequest
type DelegationGrant = authcore.DelegationGrant
type DelegatedConfig = authcore.DelegatedConfig
type DeviceKeysConfig = authcore.DeviceKeysConfig
type DeviceKeyNotice = authcore.DeviceKeyNotice
type DocumentsConfig = authcore.DocumentsConfig
type DocumentReader = authcore.DocumentReader
type EmailSender = authcore.EmailSender
type SolanaSNSResolver = authcore.SolanaSNSResolver
type EntitlementFilterProvider = authcore.EntitlementFilterProvider
type EntitlementsProvider = authcore.EntitlementsProvider
type EphemeralStore = authcore.EphemeralStore
type FrontendConfig = authcore.FrontendConfig
type GeneratedRoute = authcore.GeneratedRoute
type GroupSchema = authcore.GroupSchema
type PersonaDef = authcore.PersonaDef
type PersonaCapabilities = authcore.PersonaCapabilities
type InstanceCreationDef = authcore.InstanceCreationDef
type IdentityConfig = authcore.IdentityConfig
type KeysConfig = authcore.KeysConfig
type EphemeralConfig = authcore.EphemeralConfig
type Deps = authcore.Deps
type PasskeyConfig = authcore.PasskeyConfig
type RegistrationConfig = authcore.RegistrationConfig
type RegistrationMode = authcore.RegistrationMode
type RegistrationVerificationPolicy = authcore.RegistrationVerificationPolicy
type RoleDef = authcore.RoleDef
type RemovedMFARoleAssignment = authcore.RemovedMFARoleAssignment
type SMSHealthChecker = authcore.SMSHealthChecker
type SMSSender = authcore.SMSSender
type SessionFreshness = authcore.SessionFreshness
type SolanaLinkedAccount = authcore.SolanaLinkedAccount
type TokenConfig = authcore.TokenConfig
type TwoFactorConfig = authcore.TwoFactorConfig
type TwoFactorFactor = authcore.TwoFactorFactor
type VerificationMessage = authcore.VerificationMessage
type ContactChange = authcore.ContactChange

// Re-exported constants.
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
const OwnerRoleName = authcore.OwnerRoleName
const PermRootResourcesRead = authcore.PermRootResourcesRead
const PermRootUsersBan = authcore.PermRootUsersBan
const PermRootUsersDelete = authcore.PermRootUsersDelete
const PermRootUsersRecover = authcore.PermRootUsersRecover
const RegistrationModeClosed = authcore.RegistrationModeClosed
const RegistrationModeInviteOnly = authcore.RegistrationModeInviteOnly
const RegistrationModeOpen = authcore.RegistrationModeOpen
const RegistrationVerificationNone = authcore.RegistrationVerificationNone
const RegistrationVerificationOptional = authcore.RegistrationVerificationOptional
const RegistrationVerificationRequired = authcore.RegistrationVerificationRequired
const RootPersona = authcore.RootPersona
const SensitiveActionFreshAuthWindow = authcore.SensitiveActionFreshAuthWindow
const SessionEventCreated = authcore.SessionEventCreated
const SessionEventFailed = authcore.SessionEventFailed
const SessionRevokeReasonAdminRevokeAll = authcore.SessionRevokeReasonAdminRevokeAll
const SessionRevokeReasonLogout = authcore.SessionRevokeReasonLogout
const SessionRevokeReasonUserRevoke = authcore.SessionRevokeReasonUserRevoke
const SessionRevokeReasonUserRevokeAll = authcore.SessionRevokeReasonUserRevokeAll
const SubjectKindRemoteApp = authcore.SubjectKindRemoteApp
const SubjectKindUser = authcore.SubjectKindUser
const TwoFactorDisabled = authcore.TwoFactorDisabled
const TwoFactorOptional = authcore.TwoFactorOptional
const TwoFactorRequired = authcore.TwoFactorRequired

// Re-exported variables, sentinel errors, and functions.

// #136 no-escalation role-assignment errors.
var IntrinsicRootPermissions = authcore.IntrinsicRootPermissions
var IntrinsicRootPersona = authcore.IntrinsicRootPersona
var LoadBootstrapManifestFile = authcore.LoadBootstrapManifestFile
var MintRemoteApplicationAccessToken = authcore.MintRemoteApplicationAccessToken
var MintServiceJWT = authcore.MintServiceJWT
var NormalizeEmail = authcore.NormalizeEmail
var NormalizePhone = authcore.NormalizePhone
var NormalizePreferredLanguage = authcore.NormalizePreferredLanguage
var NormalizeRemoteAppTrustSource = authcore.NormalizeRemoteAppTrustSource
var OwnerGrant = authcore.OwnerGrant
var ValidateEmail = authcore.ValidateEmail
var ValidatePassword = authcore.ValidatePassword
var ValidatePhone = authcore.ValidatePhone
var ValidateUsername = authcore.ValidateUsername
var ValidationErrorCode = authcore.ValidationErrorCode
var WithSessionRevokeReason = authcore.WithSessionRevokeReason

// WithResolvedGroup retains an already-authorized group UUID for one request's
// original persona/reference. It grants no permission, rechecks liveness, and
// never falls back to a new name owner after deletion. Other references resolve
// normally. Use the same context for subsequent group operations.
var WithResolvedGroup = authcore.WithResolvedGroup
