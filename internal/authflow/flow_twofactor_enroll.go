package authflow

// TwoFactorEnrollmentScope is what an enrollment call may do: the factor
// slot policy and whether the account already holds a factor.
type TwoFactorEnrollmentScope struct {
	Mode       FactorEnrollmentMode
	HasFactors bool
}

// TwoFactorEnrollInput is one enrollment request: a setup to start (no Code),
// or the factor its Code proves to add.
type TwoFactorEnrollInput struct {
	LoginChallenge string
	// SessionID is the caller's session; a confirmed code marks it 2FA-verified.
	SessionID   string
	UserAgent   string
	IP          string
	UserID      string
	Mode        FactorEnrollmentMode
	Method      string // "email" | "sms" | "totp"
	Code        string // email/SMS setup code or TOTP code; empty starts the method's setup
	PhoneNumber string
	MakeDefault bool
}

// TwoFactorEnrollKind is the closed set of enrollment results.
type TwoFactorEnrollKind string

const (
	TwoFactorEnrollCodeSent    TwoFactorEnrollKind = "code_sent"    // email/SMS setup code delivered
	TwoFactorEnrollTOTPStarted TwoFactorEnrollKind = "totp_started" // secret + otpauth URI handed out
	TwoFactorEnrollEnabled     TwoFactorEnrollKind = "enabled"
)

// TwoFactorEnrollOutcome carries the setup code's Destination for
// TwoFactorEnrollCodeSent, the TOTP material for TwoFactorEnrollTOTPStarted,
// and for TwoFactorEnrollEnabled the new Factor with the plaintext backup
// codes (shown once, the first factor's only). SessionVerified reports that
// the input session now holds 2FA assurance.
type TwoFactorEnrollOutcome struct {
	Login           *LoginOutcome
	Kind            TwoFactorEnrollKind
	Method          string
	Destination     string
	Secret          string
	OTPAuthURI      string
	Factor          MFAFactor
	BackupCodes     []string
	SessionVerified bool
}
