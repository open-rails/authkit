package authflow

import "github.com/open-rails/authkit/iam"

// RegisterInput is a native-user registration attempt: Identifier is an email
// or an E.164 phone; the account is password-backed.
type RegisterInput struct {
	Identifier         string
	Username           string
	Password           string
	PreferredLanguage  string
	AccountInviteToken string
	// Agreements are the documents the sign-up accepts (Config.Agreements).
	Agreements []iam.AgreementRef
	UserAgent  string
	IP         string
}

// RegisterOutcomeKind is the closed set of ways a registration ends.
type RegisterOutcomeKind string

const (
	// RegisterSignedIn: the account exists; Login is its first sign-in (a
	// session, or the step it waits on).
	RegisterSignedIn RegisterOutcomeKind = "signed_in"
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
}
