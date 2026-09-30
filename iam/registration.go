package iam

// Registration policy vocabulary (#147).

// RegistrationVerificationPolicy controls whether a newly-registered contact must
// be verified.
type RegistrationVerificationPolicy string

const (
	RegistrationVerificationNone     RegistrationVerificationPolicy = "none"
	RegistrationVerificationOptional RegistrationVerificationPolicy = "optional"
	RegistrationVerificationRequired RegistrationVerificationPolicy = "required"
)

// RegistrationMode is the public self-registration policy: open (anyone),
// invite_only (with an account invitation) or closed. Host operations
// (CreateUser, bootstrap, import) create users in every mode.
type RegistrationMode string

const (
	RegistrationModeOpen       RegistrationMode = "open"
	RegistrationModeInviteOnly RegistrationMode = "invite_only"
	RegistrationModeClosed     RegistrationMode = "closed"
)
