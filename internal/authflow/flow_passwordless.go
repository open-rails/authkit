package authflow

import "github.com/open-rails/authkit/iam"

// PasswordlessLoginInput selects either a typed code, with the challenge its
// start answered, or a link token, never both, and supplies request metadata
// for the resulting authentication. Identifier, when set, must be the
// address the code or link went to.
type PasswordlessLoginInput struct {
	Identifier string
	Challenge  string
	Code       string
	Token      string
	// Agreements are the documents a sign-up accepts (Config.Agreements).
	Agreements []iam.AgreementRef
	UserAgent  string
	IP         string
}
