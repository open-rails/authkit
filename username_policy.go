package authkit

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Username length defaults and the ceiling for a configured maximum.
const (
	DefaultUsernameMinLength = 4
	DefaultUsernameMaxLength = 30
	UsernameMaxLengthCeiling = 64
)

// UsernamePattern is the fixed character rule for interactive usernames,
// compatible with Go RE2 and JavaScript `u`/`v` regular expressions and HTML
// `pattern`. Length is governed separately by UsernamePolicy.
const UsernamePattern = "^[A-Za-z][A-Za-z0-9_]*$"

// UsernamePolicy is the operator-configured username length rule. Zero fields
// take defaults.
type UsernamePolicy struct {
	MinLength int
	MaxLength int
}

// Normalize fills defaults and rejects an inconsistent policy.
func (p UsernamePolicy) Normalize() (UsernamePolicy, error) {
	if p.MinLength == 0 {
		p.MinLength = DefaultUsernameMinLength
	}
	if p.MaxLength == 0 {
		p.MaxLength = max(DefaultUsernameMaxLength, p.MinLength)
	}
	if p.MinLength < 1 || p.MaxLength < p.MinLength || p.MaxLength > UsernameMaxLengthCeiling {
		return UsernamePolicy{}, fmt.Errorf("authkit: invalid username policy min_length=%d max_length=%d (want 1 <= min <= max <= %d)", p.MinLength, p.MaxLength, UsernameMaxLengthCeiling)
	}
	return p, nil
}

// Validate checks a trimmed username against the length policy and
// UsernamePattern. Length failures carry min_length/max_length metadata.
func (p UsernamePolicy) Validate(username string) error {
	return p.validate(username, p.MaxLength, false)
}

// ValidateImport checks an operator-provisioned username: the configured
// minimum, a maximum of at least 64, and hyphens are also allowed.
func (p UsernamePolicy) ValidateImport(username string) error {
	return p.validate(username, max(p.MaxLength, UsernameMaxLengthCeiling), true)
}

func (p UsernamePolicy) validate(username string, maxLen int, hyphens bool) error {
	username = strings.TrimSpace(username)
	if n := utf8.RuneCountInString(username); n < p.MinLength || n > maxLen {
		code := CodeUsernameTooShort
		if n > maxLen {
			code = CodeUsernameTooLong
		}
		return E(code, WithMetadata(map[string]any{"min_length": p.MinLength, "max_length": maxLen}))
	}
	if !asciiLetter(username[0]) {
		return E(CodeUsernameMustStartWithLetter)
	}
	if strings.Contains(username, "@") {
		return E(CodeUsernameCannotContainAt)
	}
	for i := 0; i < len(username); i++ {
		if c := username[i]; !asciiLetter(c) && !(c >= '0' && c <= '9') && c != '_' && !(hyphens && c == '-') {
			return E(CodeUsernameInvalidCharacters)
		}
	}
	return nil
}

// Derive turns arbitrary text into a username that satisfies Validate.
func (p UsernamePolicy) Derive(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "user"
	}
	if !asciiLetter(out[0]) {
		out = "u" + out
	}
	for len(out) < p.MinLength {
		out += "_user"
	}
	return out[:min(len(out), p.MaxLength)]
}

// WithSuffix appends suffix to a derived username, trimming base (and, under a
// very small maximum, suffix) so the result still satisfies Validate.
func (p UsernamePolicy) WithSuffix(base, suffix string) string {
	keep := max(1, p.MaxLength-len(suffix))
	if len(base) > keep {
		base = base[:keep]
	}
	out := base + suffix
	return out[:min(len(out), p.MaxLength)]
}

func asciiLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
