package secret

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
)

// RandB64 returns n random bytes as unpadded URL-safe base64: the one token
// generator for every one-time secret the engine and the HTTP layer mint.
func RandB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Equal compares two secrets — or their digests — without
// short-circuiting on the first differing byte; differing lengths compare
// unequal. It exists so whether a secret comparison is constant-time is never a
// per-call-site judgement: one-time-code digests, the API-key secret and the
// OAuth state cookie all compare through it.
func Equal[T ~string | ~[]byte](a, b T) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
