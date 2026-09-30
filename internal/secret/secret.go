// Package secret mints and compares one-time secrets over crypto/rand: tokens,
// numeric and alphabet codes, their stored digests and constant-time
// comparison. Every secret AuthKit issues comes from here.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// Token returns n random bytes as unpadded URL-safe base64.
func Token(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Digits returns an n-digit decimal code; leading zeros are kept.
func Digits(n int) string { return Code(n, "0123456789") }

// Code returns n characters drawn uniformly from alphabet (single-byte
// characters). crypto/rand.Int samples by rejection, so no character is
// favored whatever the alphabet's size.
func Code(n int, alphabet string) string {
	size := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, size)
		if err != nil {
			// crypto/rand never fails on supported platforms; a predictable
			// code is the one answer that must not happen.
			panic("authkit: secure RNG unavailable: " + err.Error())
		}
		b[i] = alphabet[k.Int64()]
	}
	return string(b)
}

// Hash is the stored form of a one-time secret: its hex SHA-256.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Equal compares two secrets, or their digests, in constant time; differing
// lengths compare unequal. Every secret comparison goes through it.
func Equal[T ~string | ~[]byte](a, b T) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
