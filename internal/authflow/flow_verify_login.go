package authflow

// VerificationInput completes a delivered code/link. UserID and SessionID are
// supplied only from an authenticated host principal for contact changes.
// PasswordProof is a parked login's VerificationRequired.PasswordProof.
type VerificationInput struct {
	Identifier    string
	Code          string
	Token         string
	PasswordProof string
	UserID        string
	SessionID     string
	UserAgent     string
	IP            string
}
