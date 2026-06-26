package authkit

// Two-factor policy vocabulary (#148). Shared public contract for embedded and
// future remote: hosts declare 2FA policy with a TwoFactorMode plus the set of
// allowed TwoFactorMethods, replacing the old single RequireEnrollment bool.

// TwoFactorMode is the host's account-wide 2FA enrollment policy.
type TwoFactorMode string

const (
	// TwoFactorDisabled turns 2FA off entirely: no user enrollment/challenge/
	// verify routes are usable.
	TwoFactorDisabled TwoFactorMode = "disabled"
	// TwoFactorOptional lets users enroll a second factor if they choose; an
	// un-enrolled user is not blocked from normal session use.
	TwoFactorOptional TwoFactorMode = "optional"
	// TwoFactorRequired forces every user to enroll a second factor before normal
	// session use. Existing un-enrolled users are challenged on their next
	// authenticated request (the session, not just signup, is gated).
	TwoFactorRequired TwoFactorMode = "required"
)

// TwoFactorMethod is one second-factor channel a host enables.
type TwoFactorMethod string

const (
	TwoFactorEmail TwoFactorMethod = "email"
	TwoFactorSMS   TwoFactorMethod = "sms"
	TwoFactorTOTP  TwoFactorMethod = "totp"
)
