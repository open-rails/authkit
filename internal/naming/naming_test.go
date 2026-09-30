package naming

import (
	"regexp"
	"strings"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
)

func normalized(t *testing.T, c config.UsernameConfig) config.UsernameConfig {
	t.Helper()
	c, err := config.NormalizeUsername(c)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var usernameSamples = []string{
	"abcd", "Abc_1", "a123", "zz__", "abc", "1abc", "_abc", "ab-cd", "ab.cd", "ab cd", "ab@cd", "+abcd",
	"abçd", "abcd😀", strings.Repeat("a", 30), strings.Repeat("a", 31), "a" + strings.Repeat("9", 29),
}

// The published pattern plus the published bounds accept exactly what the
// validator accepts.
func TestUsernamePatternMatchesValidator(t *testing.T) {
	c := normalized(t, config.UsernameConfig{})
	re := regexp.MustCompile(UsernamePattern)
	for _, s := range usernameSamples {
		n := len([]rune(s))
		published := re.MatchString(s) && n >= c.MinLength && n <= c.MaxLength
		if valid := Validate(c, s) == nil; valid != published {
			t.Errorf("%q: validator=%v published=%v", s, valid, published)
		}
	}
}

func TestUsernameLengthErrorsCarryBounds(t *testing.T) {
	c := normalized(t, config.UsernameConfig{MinLength: 6, MaxLength: 8})
	for s, code := range map[string]string{"abcde": "username_too_short", "abcdefghi": "username_too_long"} {
		e, ok := iam.AsError(Validate(c, s))
		if !ok || e.Code() != code || e.Metadata()["min_length"] != 6 || e.Metadata()["max_length"] != 8 {
			t.Errorf("%q: %+v", s, e)
		}
	}
}

func TestDerivedUsernamesSatisfyPolicy(t *testing.T) {
	for _, c := range []config.UsernameConfig{{}, {MinLength: 1, MaxLength: 1}, {MinLength: 3, MaxLength: 5}, {MinLength: 20, MaxLength: 24}, {MinLength: 64, MaxLength: 64}} {
		c = normalized(t, c)
		for _, in := range []string{"", "Ab", "9lives", "Émile Zola", "a_very_long_display_name_that_keeps_going_on_and_on_forever"} {
			base := Derive(c, in)
			for _, name := range []string{base, WithSuffix(c, base, "7"), WithSuffix(c, base, "0042"), WithSuffix(c, base, "_user")} {
				if err := Validate(c, name); err != nil {
					t.Errorf("policy %+v input %q -> %q: %v", c, in, name, err)
				}
			}
		}
	}
}

func TestUsernameConfigNormalize(t *testing.T) {
	c := normalized(t, config.UsernameConfig{})
	if c.MinLength != 4 || c.MaxLength != 30 || c.RenameInterval != config.DefaultRenameInterval ||
		c.FormerNames != (config.FormerNamesConfig{Mode: config.FormerNamesFinite, Duration: config.DefaultFormerNameRetention}) {
		t.Fatalf("default = %+v", c)
	}
	for _, bad := range []config.UsernameConfig{{MinLength: -1}, {MinLength: 10, MaxLength: 9}, {MaxLength: 65},
		{FormerNames: config.FormerNamesConfig{Mode: config.FormerNamesForever, Duration: 1}}, {FormerNames: config.FormerNamesConfig{Mode: "later"}}} {
		if _, err := config.NormalizeUsername(bad); err == nil {
			t.Errorf("NormalizeUsername(%+v) accepted", bad)
		}
	}
}
