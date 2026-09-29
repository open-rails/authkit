package contact

import (
	"strings"
	"unicode/utf8"
)

// MaskDestination hides a code destination for display: an email address
// keeps the first character of its local part and its domain
// (a***@example.com); a phone number keeps its last five characters.
func MaskDestination(value string) string {
	if at := strings.LastIndex(value, "@"); at > 0 {
		_, size := utf8.DecodeRuneInString(value)
		return value[:size] + "***" + value[at:]
	}
	if len(value) <= 5 {
		return value
	}
	return strings.Repeat("*", len(value)-5) + value[len(value)-5:]
}
