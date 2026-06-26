package authcore

import authkit "github.com/open-rails/authkit"

// Registration policy vocabulary is defined in authkit (core-free) and
// re-exported here (#147). The former AdminOnly/AdminBootstrapOnly/ManifestOnly
// modes were removed — RegistrationMode is now public self-registration policy
// only (Open/InviteOnly/Closed).
type RegistrationVerificationPolicy = authkit.RegistrationVerificationPolicy

const (
	RegistrationVerificationNone     = authkit.RegistrationVerificationNone
	RegistrationVerificationOptional = authkit.RegistrationVerificationOptional
	RegistrationVerificationRequired = authkit.RegistrationVerificationRequired
)

type RegistrationMode = authkit.RegistrationMode

const (
	RegistrationModeOpen       = authkit.RegistrationModeOpen
	RegistrationModeInviteOnly = authkit.RegistrationModeInviteOnly
	RegistrationModeClosed     = authkit.RegistrationModeClosed
)
