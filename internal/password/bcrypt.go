package password

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// VerifyBcrypt compares a bcrypt hash with a plaintext password.
func VerifyBcrypt(hash, password string) (bool, error) {
	if err := validateBcrypt(hash); err != nil {
		return false, err
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return err == nil, err
}

// IsBcryptHash detects common bcrypt PHC prefixes.
func IsBcryptHash(hash string) bool {
	return strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$")
}

// bcrypt.Cost parses the header without computing bcrypt. Bound the cost before
// CompareHashAndPassword, and refuse truncated or extended serialized hashes.
func validateBcrypt(hash string) error {
	if len(hash) != 60 || !IsBcryptHash(hash) || hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9' || hash[6] != '$' {
		return ErrInvalidHash
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost < bcrypt.MinCost || cost > 14 {
		return ErrInvalidHash
	}
	for _, c := range hash[7:] {
		if !(c == '.' || c == '/' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return ErrInvalidHash
		}
	}
	return nil
}
