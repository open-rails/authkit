// Package devicekey is the client side of AuthKit's device-key protocol, for
// CLIs and machines. A machine holds an Ed25519 key, enrolls it once with a
// code emailed to the account (plus the account's second factor, when it has
// one), then signs in with it for short access tokens. There is no refresh
// token: signing a fresh challenge is the refresh.
//
// A device key signs domain || 0x00 || challenge, where challenge is the
// server's raw 32-byte challenge. The domain separates enrollment from login,
// so neither signature can be replayed as the other.
//
// The package depends only on the standard library and iam.
package devicekey

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/open-rails/authkit/iam"
)

// Signing domains. AuthKit verifies with these same constants.
const (
	EnrollmentDomain = "authkit.device-key-enrollment/1"
	LoginDomain      = "authkit.device-key-login/1"
)

const challengeSize = 32

// Message is the byte string a device key signs for the raw challenge in
// domain.
func Message(domain string, challenge []byte) []byte {
	m := make([]byte, 0, len(domain)+1+len(challenge))
	m = append(m, domain...)
	m = append(m, 0)
	return append(m, challenge...)
}

// SignEnrollment signs an enrollment challenge as it arrives on the wire
// (base64url) and returns the base64url signature the finish request carries.
func SignEnrollment(key crypto.Signer, challenge string) (string, error) {
	return sign(key, EnrollmentDomain, challenge)
}

// SignLogin is SignEnrollment for a login challenge.
func SignLogin(key crypto.Signer, challenge string) (string, error) {
	return sign(key, LoginDomain, challenge)
}

func sign(key crypto.Signer, domain, challenge string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != challengeSize {
		return "", errors.New("devicekey: the challenge is not 32 base64url bytes")
	}
	if !isEd25519(key) {
		return "", errors.New("devicekey: the key is not an Ed25519 signer")
	}
	sig, err := key.Sign(nil, Message(domain, raw), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("devicekey: sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return "", errors.New("devicekey: the signer returned no Ed25519 signature")
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func isEd25519(key crypto.Signer) bool {
	if key == nil {
		return false
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	return ok && len(pub) == ed25519.PublicKeySize
}

// Enrollment is a pending enrollment: BeginEnrollment's answer, finished with
// the emailed code before ExpiresAt. It holds no secret and may be persisted
// between the two calls.
type Enrollment struct {
	ID        string
	Challenge string
	PublicKey ed25519.PublicKey
	ExpiresAt time.Time
}

// Session is a device key's sign-in: an access token and the key. It has no
// refresh token; sign in again with the key once ExpiresAt passes.
type Session struct {
	AccessToken string
	ExpiresAt   time.Time
	DeviceKey   iam.DeviceKey
}

// SecondFactorRequired is FinishEnrollment's answer when the account has a
// second factor: retry with the same enrollment and emailed code plus that
// factor's code. Method is "totp", "sms" (AuthKit has just sent the code) or
// "backup_code"; the account's email factor never counts, since it reads the
// mailbox the enrollment code went to. It wraps the decoded iam.Error.
type SecondFactorRequired struct {
	Method string
	err    error
}

func (e *SecondFactorRequired) Error() string {
	return "devicekey: enrollment needs the account's second factor (" + e.Method + ")"
}

func (e *SecondFactorRequired) Unwrap() error { return e.err }
