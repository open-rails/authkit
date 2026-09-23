package password

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Default password length bounds, in characters (Unicode code points).
const (
	DefaultMinLength = 8
	DefaultMaxLength = 128
	// MaxLengthCeiling bounds MaxLength so request bodies and KDF input stay small.
	MaxLengthCeiling = 1024
	// MinIdentifierLength is the shortest identifier a password may not contain.
	MinIdentifierLength = 4
)

// Character classes named by RequirementsError.Missing.
const (
	ClassUppercase = "uppercase"
	ClassLowercase = "lowercase"
	ClassDigit     = "digit"
	ClassSymbol    = "symbol"
)

var (
	ErrTooShort           = errors.New("password_too_short")
	ErrTooLong            = errors.New("password_too_long")
	ErrTooCommon          = errors.New("password_too_common")
	ErrContainsIdentifier = errors.New("password_contains_identifier")
)

// RequirementsError lists the required character classes a password lacks.
type RequirementsError struct{ Missing []string }

func (e *RequirementsError) Error() string {
	return "password_requirements_unmet: " + strings.Join(e.Missing, ",")
}

// Policy is the operator-configured password rule. The zero value is the
// NIST SP 800-63B-style default: 8..128 characters, no composition rules,
// common passwords rejected. Composition rules are opt-in.
type Policy struct {
	MinLength int
	MaxLength int
	// Uppercase/lowercase/digit use Unicode categories (unicode.IsUpper,
	// IsLower, IsDigit); a symbol is any rune that is neither a letter nor a
	// digit, including spaces and punctuation.
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSymbol    bool
	// AllowCommon disables the embedded common-password blocklist.
	AllowCommon bool
}

//go:generate go run ./internal/commongen

//go:embed common_passwords.txt.gz
var commonGz []byte

// commonList is the sorted, newline-terminated lowercase blocklist,
// decompressed on first use.
var commonList = sync.OnceValue(func() string {
	zr, err := gzip.NewReader(bytes.NewReader(commonGz))
	if err != nil {
		panic(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		panic(err)
	}
	return string(b)
})

// IsCommon reports whether pw (case-insensitive) is on the embedded blocklist.
func IsCommon(pw string) bool {
	list, want := commonList(), strings.ToLower(pw)
	lo, hi := 0, len(list)
	for lo < hi {
		mid := lo + (hi-lo)/2
		start := strings.LastIndexByte(list[:mid], '\n') + 1
		end := start + strings.IndexByte(list[start:], '\n')
		switch line := list[start:end]; {
		case line == want:
			return true
		case line < want:
			lo = end + 1
		default:
			hi = start
		}
	}
	return false
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

// Validate checks pw against a normalized policy. identifiers are the
// account's username and email local-part; pw may not contain any of at
// least MinIdentifierLength characters, compared case-insensitively.
func (p Policy) Validate(pw string, identifiers ...string) error {
	n := utf8.RuneCountInString(pw)
	if n < p.MinLength {
		return ErrTooShort
	}
	if n > p.MaxLength {
		return ErrTooLong
	}
	if missing := p.missingClasses(pw); len(missing) > 0 {
		return &RequirementsError{Missing: missing}
	}
	lower := strings.ToLower(pw)
	for _, id := range identifiers {
		id = strings.ToLower(strings.TrimSpace(id))
		if utf8.RuneCountInString(id) >= MinIdentifierLength && strings.Contains(lower, id) {
			return ErrContainsIdentifier
		}
	}
	if !p.AllowCommon {
		if IsCommon(lower) {
			return ErrTooCommon
		}
	}
	return nil
}

func (p Policy) missingClasses(pw string) []string {
	var upper, lower, digit, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case !unicode.IsLetter(r):
			symbol = true
		}
	}
	var missing []string
	for _, c := range []struct {
		required, present bool
		class             string
	}{{p.RequireUppercase, upper, ClassUppercase}, {p.RequireLowercase, lower, ClassLowercase}, {p.RequireDigit, digit, ClassDigit}, {p.RequireSymbol, symbol, ClassSymbol}} {
		if c.required && !c.present {
			missing = append(missing, c.class)
		}
	}
	return missing
}

// EmailLocalPart returns the part of email before its last '@', or "".
func EmailLocalPart(email string) string {
	if at := strings.LastIndexByte(email, '@'); at > 0 {
		return email[:at]
	}
	return ""
}
