package authflow

// TwoFactorEnrollmentScope is what an enrollment call may do: the factor
// slot policy and whether the account already holds a factor.
type TwoFactorEnrollmentScope struct {
	Mode       FactorEnrollmentMode
	HasFactors bool
}

// TwoFactorEnrollInput is one enrollment request.
type TwoFactorEnrollInput struct {
	LoginChallenge string
	// SessionID is the caller's session; a confirmed code marks it 2FA-verified.
	SessionID   string
	UserAgent   string
	IP          string
	UserID      string
	Mode        FactorEnrollmentMode
	Method      string // "email" | "sms" | "totp"; empty with FactorID+MakeDefault re-points the default
	Code        string // email/SMS setup code or TOTP code; empty starts the method's setup
	PhoneNumber string
	MakeDefault bool
	FactorID    string
}

// TwoFactorEnrollKind is the closed set of enrollment results.
type TwoFactorEnrollKind string

const (
	TwoFactorEnrollDefaultSet  TwoFactorEnrollKind = "default_set"
	TwoFactorEnrollCodeSent    TwoFactorEnrollKind = "code_sent"    // email/SMS setup code delivered
	TwoFactorEnrollTOTPStarted TwoFactorEnrollKind = "totp_started" // secret + otpauth URI handed out
	TwoFactorEnrollEnabled     TwoFactorEnrollKind = "enabled"
)

// TwoFactorEnrollOutcome carries the TOTP material for TwoFactorEnrollTOTPStarted
// and the plaintext backup codes (shown once) for TwoFactorEnrollEnabled.
// SessionVerified reports that the input session now holds 2FA assurance.
type TwoFactorEnrollOutcome struct {
	Login           *LoginOutcome
	Kind            TwoFactorEnrollKind
	Method          string
	Secret          string
	OTPAuthURI      string
	BackupCodes     []string
	SessionVerified bool
}
