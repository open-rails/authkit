package authflow

import "github.com/open-rails/authkit/iam"

// PasswordlessLoginInput selects either a typed code or a link token, never
// both, and supplies request metadata for the resulting authentication.
type PasswordlessLoginInput struct {
	Identifier string
	Code       string
	Token      string
	// Agreements are the documents a sign-up accepts (Config.Agreements).
	Agreements []iam.AgreementRef
	UserAgent  string
	IP         string
}
