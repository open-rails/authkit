// Package apikey is the API-key token format, shared by the engine (mint and
// resolve) and verify (routing a bearer token to the API-key path).
//
// A token is <marker><lookup id>_<secret>. The marker is "<prefix>_st_", or
// "st_" without a host prefix. The lookup id is public and indexed; only a
// SHA-256 of the secret is stored. Both parts are base62, so the first "_"
// after the marker is the delimiter.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
	"strings"
)

const (
	typeSegment = "st_"
	lookupIDLen = 16 // base62
	secretLen   = 43 // base62, ~256 bits
	alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// Marker is the leading marker of a token for the host prefix.
func Marker(prefix string) string {
	if prefix = strings.TrimSpace(prefix); prefix != "" {
		return prefix + "_" + typeSegment
	}
	return typeSegment
}

// HasMarker reports whether token is shaped like an API key for prefix.
func HasMarker(prefix, token string) bool {
	return strings.HasPrefix(token, Marker(prefix))
}

// Minted is a new key: store LookupID and SecretHash, and hand Token out once.
type Minted struct {
	Token      string
	LookupID   string
	SecretHash []byte
}

// Mint generates a new key for prefix.
func Mint(prefix string) (Minted, error) {
	lookupID, err := randBase62(lookupIDLen)
	if err != nil {
		return Minted{}, err
	}
	secret, err := randBase62(secretLen)
	if err != nil {
		return Minted{}, err
	}
	return Minted{Token: Marker(prefix) + lookupID + "_" + secret, LookupID: lookupID, SecretHash: Hash(secret)}, nil
}

// Parse splits a token into its lookup id and secret. ok is false unless the
// token carries the marker and both parts are non-empty base62.
func Parse(prefix, token string) (lookupID, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, Marker(prefix))
	if !found {
		return "", "", false
	}
	lookupID, secret, found = strings.Cut(rest, "_")
	if !found || !base62(lookupID) || !base62(secret) {
		return "", "", false
	}
	return lookupID, secret, true
}

// Hash is the stored form of a secret.
func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Matches reports, in constant time, whether secret hashes to stored.
func Matches(stored []byte, secret string) bool {
	return subtle.ConstantTimeCompare(stored, Hash(secret)) == 1
}

func base62(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

func randBase62(n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}
