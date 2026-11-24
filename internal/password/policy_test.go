package password

import (
	"errors"
	"testing"

	"github.com/open-rails/authkit/internal/config"
)

func TestValidateCommonIgnoresCaseAndSeparators(t *testing.T) {
	p, err := config.NormalizePassword(config.PasswordPolicy{})
	if err != nil {
		t.Fatal(err)
	}
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
		err := Validate(p, c.pw)
		if got := errors.Is(err, ErrTooCommon); got != c.common {
			t.Errorf("Validate(%q) = %v, want common %v", c.pw, err, c.common)
		}
	}
}
