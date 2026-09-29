package contact

import (
	"strings"
)

// MaskDestination hides all but the last five characters of a code
// destination (email or phone) for display as a verification id.
func MaskDestination(value string) string {
	if len(value) <= 5 {
		return value
	}
	return strings.Repeat("*", len(value)-5) + value[len(value)-5:]
}
