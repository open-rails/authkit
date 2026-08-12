package authcore

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// Random token / code generation and a hashing helper shared across the
// verification, reset, and pending-change flows.

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// randInt returns a uniformly distributed integer in [0, max). max must be
// positive; rand.Int panics otherwise, which is the right answer — silently
// returning 0 would make randAlphanumeric emit "000000".
//
// It replaces a hand-rolled `n % max` over four random bytes. That reduction
// was biased for any max that is not a power of two (negligibly so at max=10 —
// 2^32 mod 10 = 6 over 2^32 draws — so this is a correctness fix, not an
// exploitable one), and it carried a real defect: the sign fold
// `if n < 0 { n = -n }` is dead on a 64-bit int, but on a 32-bit int the shift
// overflows into the sign bit and negating MinInt32 stays negative, so randInt
// could return a NEGATIVE digit and randAlphanumeric would splice a non-digit
// character into a verification code.
//
// crypto/rand.Int does uniform rejection sampling, so uniformity is a property
// of the construction rather than something a statistical test has to chase.
func randInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Unreachable on go1.26 — crypto/rand.Reader never returns an error, it
		// crashes the process. Handled only because rand.Int carries an error in
		// its signature, and a panic is the only answer that cannot hand a caller
		// a predictable verification code.
		panic("authkit: secure RNG unavailable while generating a code: " + err.Error())
	}
	return int(n.Int64())
}

// randAlphanumeric generates a random numeric code of length n.
// It returns a string to preserve leading zeros.
func randAlphanumeric(n int) string {
	// Generate n-digit numeric code (e.g., 6 digits = 000000-999999)
	code := ""
	for i := 0; i < n; i++ {
		code += string('0' + byte(randInt(10)))
	}
	return code
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// secretHashEqual compares two sha256Hex digests of one-time secrets without
// short-circuiting on the first differing byte. Differing lengths compare
// unequal. Behaviourally identical to ==; the point is that whether a given
// secret comparison is constant-time stops being a per-call-site judgement.
// api_keys.go and the OAuth state cookie already compare this way.
func secretHashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// randAlphanumericUppercase generates a random uppercase alphanumeric string (A-Z, 0-9)
// Used for backup codes which are longer and case-sensitive
func randAlphanumericUppercase(n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude ambiguous chars
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = chars[randInt(len(chars))]
	}
	return string(b)
}
