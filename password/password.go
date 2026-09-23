package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Params defines Argon2id parameters.
type Params struct {
	Time    uint32 // iterations
	Memory  uint32 // KiB
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

func DefaultParams() Params {
	return Params{Time: 1, Memory: 64 * 1024, Threads: 1, SaltLen: 16, KeyLen: 32}
}

// HashArgon2id returns a PHC-encoded string.
func HashArgon2id(password string) (string, error) {
	p := DefaultParams()
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return phcEncode(p, salt, dk), nil
}

// VerifyArgon2id checks a password against a PHC-encoded hash.
func VerifyArgon2id(encoded, password string) (bool, error) {
	p, salt, sum, err := phcDecode(encoded)
	if err != nil {
		return false, err
	}
	dk := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(sum)))
	return subtle.ConstantTimeCompare(dk, sum) == 1, nil
}

// Default password length bounds, in characters (Unicode code points).
const (
	DefaultMinLength = 8
	DefaultMaxLength = 128
	// MaxLengthCeiling bounds MaxLength so request bodies and KDF input stay small.
	MaxLengthCeiling = 1024
)

var (
	ErrTooShort = errors.New("password_too_short")
	ErrTooLong  = errors.New("password_too_long")
)

// Policy is the operator-configured password rule. Zero fields take defaults.
type Policy struct {
	MinLength int
	MaxLength int
}

// Normalize fills defaults and rejects an inconsistent policy.
func (p Policy) Normalize() (Policy, error) {
	if p.MinLength == 0 {
		p.MinLength = DefaultMinLength
	}
	if p.MaxLength == 0 {
		p.MaxLength = max(DefaultMaxLength, p.MinLength)
	}
	if p.MinLength < 1 || p.MaxLength < p.MinLength || p.MaxLength > MaxLengthCeiling {
		return Policy{}, fmt.Errorf("authkit: invalid password policy min_length=%d max_length=%d (want 1 <= min <= max <= %d)", p.MinLength, p.MaxLength, MaxLengthCeiling)
	}
	return p, nil
}

// Validate checks pw's length in characters against a normalized policy.
func (p Policy) Validate(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < p.MinLength {
		return ErrTooShort
	}
	if n > p.MaxLength {
		return ErrTooLong
	}
	return nil
}

func phcEncode(p Params, salt, sum []byte) string {
	// $argon2id$v=19$m=65536,t=1,p=1$<salt_b64>$<sum_b64>
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
}

// ErrInvalidHash means a stored hash is malformed or outside the supported work
// policy. Callers may require a password reset; verification never runs its KDF.
var ErrInvalidHash = errors.New("invalid_password_hash")

// ValidateHash checks a supported hash without computing the password KDF.
// The algorithm must be explicit; imports normalize their source format.
func ValidateHash(hash, algorithm string) error {
	switch algorithm {
	case "argon2id":
		_, _, _, err := phcDecode(hash)
		return err
	case "bcrypt":
		return validateBcrypt(hash)
	default:
		return ErrInvalidHash
	}
}

func phcDecode(s string) (Params, []byte, []byte, error) {
	var p Params
	if len(s) > 256 {
		return p, nil, nil, ErrInvalidHash
	}
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return p, nil, nil, ErrInvalidHash
	}
	var m, t, threads uint32
	n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &threads)
	if err != nil || n != 3 || fmt.Sprintf("m=%d,t=%d,p=%d", m, t, threads) != parts[3] ||
		threads < 1 || threads > 16 || m < 8*threads || m > 256*1024 || t < 1 || t > 10 || uint64(m)*uint64(t) > 1024*1024 {
		return p, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 || base64.RawStdEncoding.EncodeToString(salt) != parts[4] {
		return p, nil, nil, ErrInvalidHash
	}
	sum, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(sum) < 16 || len(sum) > 64 || base64.RawStdEncoding.EncodeToString(sum) != parts[5] {
		return p, nil, nil, ErrInvalidHash
	}
	p = Params{Time: t, Memory: m, Threads: uint8(threads), SaltLen: uint32(len(salt)), KeyLen: uint32(len(sum))}
	return p, salt, sum, nil
}
