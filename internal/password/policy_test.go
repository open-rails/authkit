package password

import (
	"errors"
	"testing"
)

// Normalization edges beside AK-J03-C07, which refuses common passwords
// whatever their case and separators.
func TestValidateCommonNormalizationEdges(t *testing.T) {
	for _, c := range []struct {
		pw     string
		common bool
	}{
		{"p@ssw0rd", true},            // on the list with its punctuation
		{"x!y@z#w$", false},           // its core is shorter than MinLength
		{"ünïcode-Pässwörd-7", false}, // letters of any script stay
	} {
		err := Validate(c.pw)
		if got := errors.Is(err, ErrTooCommon); got != c.common {
			t.Errorf("Validate(%q) = %v, want common %v", c.pw, err, c.common)
		}
	}
}
