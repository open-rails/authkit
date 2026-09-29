package authflow

// RegisterInput is a native-user registration attempt: Identifier is an email
// or an E.164 phone; the account is password-backed.
type RegisterInput struct {
	Identifier         string
	Username           string
	Password           string
	PreferredLanguage  string
	AccountInviteToken string
	UserAgent          string
	IP                 string
}

// RegisterOutcomeKind is the closed set of ways a registration ends.
type RegisterOutcomeKind string

const (
	RegisterLoginRequired RegisterOutcomeKind = "login_required"
	// RegisterSessionIssued: the account exists and is signed in (no
	// verification pending).
	RegisterSessionIssued RegisterOutcomeKind = "session_issued"
	// RegisterVerifyEmail / RegisterVerifyPhone: the registration is pending
	// until the code just sent to the identifier is confirmed.
	RegisterVerifyEmail RegisterOutcomeKind = "verify_email"
	RegisterVerifyPhone RegisterOutcomeKind = "verify_phone"
)

// RegisterOutcome reports who was registered and what happens next.
type RegisterOutcome struct {
	Login    *LoginOutcome
	Kind     RegisterOutcomeKind
	Username string
	Email    *string
	Phone    *string
	Session  *IssuedSession
}
