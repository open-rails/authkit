package password

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/open-rails/authkit/internal/config"
)

// MinIdentifierLength is the shortest identifier a password may not contain.
const MinIdentifierLength = 4

var (
	ErrTooShort           = errors.New("password_too_short")
	ErrTooLong            = errors.New("password_too_long")
	ErrTooCommon          = errors.New("password_too_common")
	ErrContainsIdentifier = errors.New("password_contains_identifier")
)

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

// Validate checks pw against AuthKit's policy (config.PasswordMinLength to
// config.PasswordMaxLength code points, not on the blocklist). identifiers
// are the account's username and email local-part; pw may not contain any of
// at least MinIdentifierLength characters, compared case-insensitively.
func Validate(pw string, identifiers ...string) error {
	n := utf8.RuneCountInString(pw)
	if n < config.PasswordMinLength {
		return ErrTooShort
	}
	if n > config.PasswordMaxLength {
		return ErrTooLong
	}
	lower := strings.ToLower(pw)
	for _, id := range identifiers {
		id = strings.ToLower(strings.TrimSpace(id))
		if utf8.RuneCountInString(id) >= MinIdentifierLength && strings.Contains(lower, id) {
			return ErrContainsIdentifier
		}
	}
	if common(lower) {
		return ErrTooCommon
	}
	return nil
}

// common reports whether lower, or lower without its punctuation and spaces
// ("change-me" as "changeme"), is on the blocklist. The stripped form counts
// only when it is still PasswordMinLength long, so a short common core inside
// punctuation is not a match.
func common(lower string) bool {
	if IsCommon(lower) {
		return true
	}
	core := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, lower)
	return core != lower && utf8.RuneCountInString(core) >= config.PasswordMinLength && IsCommon(core)
}

// EmailLocalPart returns the part of email before its last '@', or "".
func EmailLocalPart(email string) string {
	if at := strings.LastIndexByte(email, '@'); at > 0 {
		return email[:at]
	}
	return ""
}
