package authflow

// PasswordlessLoginInput selects either a typed code or a link token, never
// both, and supplies request metadata for the resulting authentication.
type PasswordlessLoginInput struct {
	Identifier string
	Code       string
	Token      string
	UserAgent  string
	IP         string
}
