package authkit

import (
	"regexp"
	"strings"
	"testing"
)

var usernameSamples = []string{
	"abcd", "Abc_1", "a123", "zz__", "abc", "1abc", "_abc", "ab-cd", "ab.cd", "ab cd", "ab@cd", "+abcd",
	"abçd", "abcd😀", strings.Repeat("a", 30), strings.Repeat("a", 31), "a" + strings.Repeat("9", 29),
}

// The published pattern plus the published bounds accept exactly what the
// validator accepts.
func TestUsernamePatternMatchesValidator(t *testing.T) {
	p, err := UsernamePolicy{}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(UsernamePattern)
	for _, s := range usernameSamples {
		n := len([]rune(s))
		published := re.MatchString(s) && n >= p.MinLength && n <= p.MaxLength
		if valid := p.Validate(s) == nil; valid != published {
			t.Errorf("%q: validator=%v published=%v", s, valid, published)
		}
	}
}

func TestUsernameLengthErrorsCarryBounds(t *testing.T) {
	p, _ := UsernamePolicy{MinLength: 6, MaxLength: 8}.Normalize()
	for s, code := range map[string]Code{"abcde": CodeUsernameTooShort, "abcdefghi": CodeUsernameTooLong} {
		e := AsError(p.Validate(s))
		if e == nil || e.Code != code || e.Meta["min_length"] != 6 || e.Meta["max_length"] != 8 {
			t.Errorf("%q: %+v", s, e)
		}
	}
}

func TestDerivedUsernamesSatisfyPolicy(t *testing.T) {
	for _, p := range []UsernamePolicy{{}, {MinLength: 1, MaxLength: 1}, {MinLength: 3, MaxLength: 5}, {MinLength: 20, MaxLength: 24}, {MinLength: 64, MaxLength: 64}} {
		p, err := p.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range []string{"", "Ab", "9lives", "Émile Zola", "a_very_long_display_name_that_keeps_going_on_and_on_forever"} {
			base := p.Derive(in)
			for _, name := range []string{base, p.WithSuffix(base, "7"), p.WithSuffix(base, "0042"), p.WithSuffix(base, "_user")} {
				if err := p.Validate(name); err != nil {
					t.Errorf("policy %+v input %q -> %q: %v", p, in, name, err)
				}
			}
		}
	}
}

func TestUsernamePolicyNormalize(t *testing.T) {
	if p, err := (UsernamePolicy{}).Normalize(); err != nil || p != (UsernamePolicy{4, 30}) {
		t.Fatalf("default = %+v, %v", p, err)
	}
	for _, bad := range []UsernamePolicy{{MinLength: -1}, {MinLength: 10, MaxLength: 9}, {MaxLength: 65}} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("Normalize(%+v) accepted", bad)
		}
	}
}
