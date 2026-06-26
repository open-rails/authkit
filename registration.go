package authkit

// Registration policy vocabulary (#147). Shared public contract for embedded and
// future remote, so host docs and the `remote` package import the vocabulary from
// root authkit rather than from `embedded`.

// RegistrationVerificationPolicy controls whether a newly-registered contact must
// be verified.
type RegistrationVerificationPolicy string

const (
	RegistrationVerificationNone     RegistrationVerificationPolicy = "none"
	RegistrationVerificationOptional RegistrationVerificationPolicy = "optional"
	RegistrationVerificationRequired RegistrationVerificationPolicy = "required"
)

// RegistrationMode is the public native-user self-registration policy (#147).
// It governs ONLY public self-registration; operators can always create users
// through privileged APIs, bootstrap, or manual DB operations regardless of mode.
//
//	Open       — anyone may self-register.
//	InviteOnly — self-registration requires a valid unbound account-registration
//	             invite code.
//	Closed      — no public self-registration at all.
//
// The former AdminOnly / AdminBootstrapOnly / ManifestOnly modes were removed
// (#147): they described operator-side creation, not a public self-registration
// policy, and are subsumed by "use the privileged APIs" under any mode.
type RegistrationMode string

const (
	RegistrationModeOpen       RegistrationMode = "open"
	RegistrationModeInviteOnly RegistrationMode = "invite_only"
	RegistrationModeClosed     RegistrationMode = "closed"
)
