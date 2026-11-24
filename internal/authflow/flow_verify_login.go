package authflow

// VerificationInput completes a delivered code, with the challenge its start
// answered, or a link. Identifier, when set, must be the address it went to.
// UserID and SessionID are supplied only from an authenticated host identity
// for contact changes. PasswordProof is a parked login's
// VerificationRequired.PasswordProof.
type VerificationInput struct {
	Identifier    string
	Challenge     string
	Code          string
	Token         string
	PasswordProof string
	UserID        string
	SessionID     string
	UserAgent     string
	IP            string
}
