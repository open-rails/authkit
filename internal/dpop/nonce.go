package dpop

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// NonceSource issues server nonces and checks them (RFC 9449 §8 at a token
// endpoint, §9 at a resource server).
type NonceSource interface {
	// Issue is a nonce current from now.
	Issue(ctx context.Context) string
	// Valid reports whether nonce is current.
	Valid(ctx context.Context, nonce string) bool
}

// NonceLifetime is how long a server nonce stays current.
const NonceLifetime = 5 * time.Minute

// Nonces issues and checks RFC 9449 §8 server nonces without state: a nonce
// is its issue time and an HMAC of it under a key every replica shares.
// Replay is still the replay guard's job; a nonce bounds how far ahead a
// proof can be made.
type Nonces struct{ key []byte }

// NewNonces keys nonces with key, at least 32 random bytes.
func NewNonces(key []byte) (*Nonces, error) {
	if len(key) < 32 {
		return nil, errors.New("DPoP nonce key needs at least 32 bytes")
	}
	return &Nonces{key: append([]byte(nil), key...)}, nil
}

// Issue is a nonce current from now.
func (n *Nonces) Issue(context.Context) string { return n.issue(time.Now()) }

// Valid reports whether nonce was issued under this key within NonceLifetime.
func (n *Nonces) Valid(_ context.Context, nonce string) bool { return n.valid(nonce, time.Now()) }

func (n *Nonces) issue(now time.Time) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.Unix()))
	return base64.RawURLEncoding.EncodeToString(append(b[:], n.mac(b[:])...))
}

func (n *Nonces) valid(nonce string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(raw) != 24 || !hmac.Equal(raw[8:], n.mac(raw[:8])) {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	return !issued.Before(now.Add(-NonceLifetime)) && !issued.After(now.Add(time.Minute))
}

func (n *Nonces) mac(issued []byte) []byte {
	m := hmac.New(sha256.New, n.key)
	m.Write([]byte("authkit-dpop-nonce\x00"))
	m.Write(issued)
	return m.Sum(nil)[:16]
}
