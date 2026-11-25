package password

import (
	"errors"
	"testing"
)

func TestValidateCommonIgnoresCaseAndSeparators(t *testing.T) {
	for _, c := range []struct {
		pw     string
		common bool
	}{
		{"changeme", true},
		{"change-me", true},
		{"Change.Me", true},
		{"CHANGE ME", true},
		{"pass_word-1", true},
		{"p@ssw0rd", true},            // on the list with its punctuation
		{"x!y@z#w$", false},           // its core is shorter than MinLength
		{"Tr4il-Mix-Quokka", false},   // not common
		{"ünïcode-Pässwörd-7", false}, // letters of any script stay
	} {
		err := Validate(c.pw)
		if got := errors.Is(err, ErrTooCommon); got != c.common {
			t.Errorf("Validate(%q) = %v, want common %v", c.pw, err, c.common)
		}
	}
}
