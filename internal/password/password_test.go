package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-rails/authkit/internal/config"
)

func TestArgon2id_RoundTrip(t *testing.T) {
	const pass = "correct horse battery staple"

	h, err := HashArgon2id(pass)
	if err != nil {
		t.Fatalf("HashArgon2id failed: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		wantMatch bool
	}{
		{"correct password", pass, true},
		{"wrong password", "wrong password", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := VerifyArgon2id(h, tt.password)
			if err != nil {
				t.Fatalf("VerifyArgon2id returned error: %v", err)
			}
			if match != tt.wantMatch {
				t.Errorf("VerifyArgon2id match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func policy(t *testing.T, p *config.PasswordPolicy) config.PasswordPolicy {
	t.Helper()
	n, err := config.NormalizePassword(p)
	if err != nil {
		t.Fatal(err)
	}
	return *n
}

func TestPolicyValidateCountsCharacters(t *testing.T) {
	p := policy(t, &config.PasswordPolicy{MinLength: 4, MaxLength: 6})
	for pw, want := range map[string]error{
		"abc": ErrTooShort, "abcd": nil, "ééé": ErrTooShort, "éééé": nil,
		"😀😀😀😀😀😀": nil, "abcdefg": ErrTooLong,
	} {
		if got := Validate(p, pw); got != want {
			t.Errorf("Validate(%q) = %v, want %v", pw, got, want)
		}
	}
}

func TestPolicyNormalize(t *testing.T) {
	if p := policy(t, nil); p != (config.PasswordPolicy{MinLength: config.DefaultPasswordMinLength, MaxLength: config.DefaultPasswordMaxLength, RejectCommon: true}) {
		t.Fatalf("default = %+v", p)
	}
	if p := policy(t, &config.PasswordPolicy{MinLength: 200}); p.MaxLength != 200 || p.RejectCommon {
		t.Fatalf("a set policy is taken as written = %+v", p)
	}
	for _, bad := range []config.PasswordPolicy{{MinLength: -1}, {MinLength: 10, MaxLength: 9}, {MaxLength: config.PasswordMaxLengthCeiling + 1}} {
		if _, err := config.NormalizePassword(&bad); err == nil {
			t.Errorf("NormalizePassword(%+v) accepted", bad)
		}
	}
}

func TestPolicyRejectsCommonIdentifiersAndMissingClasses(t *testing.T) {
	p := policy(t, nil)
	if err := Validate(p, "QwertyUIOP"); err != ErrTooCommon {
		t.Fatalf("common = %v", err)
	}
	if err := Validate(p, "xx-Alice-xx", "alice"); err != ErrContainsIdentifier {
		t.Fatalf("identifier = %v", err)
	}
	if err := Validate(p, "abc-12345", "abc"); err != nil {
		t.Fatalf("short identifiers are ignored: %v", err)
	}
	if err := Validate(policy(t, &config.PasswordPolicy{}), "qwertyuiop"); err != nil {
		t.Fatalf("without RejectCommon = %v", err)
	}
	strict := policy(t, &config.PasswordPolicy{RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSymbol: true})
	var unmet *RequirementsError
	if err := Validate(strict, "ÉCOLE-DE-NUIT"); !errors.As(err, &unmet) || strings.Join(unmet.Missing, ",") != "lowercase,digit" {
		t.Fatalf("missing = %v", err)
	}
	if err := Validate(strict, "Écoledenuit7 "); err != nil {
		t.Fatalf("a space is a symbol: %v", err)
	}
}

func TestBlocklistCoversCommonLongPasswords(t *testing.T) {
	p := policy(t, nil)
	for _, pw := range []string{"password123", "Password1!", "qwerty12345", "iloveyou123", "PASSWORD", "qwertyuiop"} {
		if err := Validate(p, pw); err != ErrTooCommon {
			t.Errorf("Validate(%q) = %v, want ErrTooCommon", pw, err)
		}
	}
	for _, pw := range []string{"violet-harbor-lantern", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "\U0010ffff"} {
		if IsCommon(pw) {
			t.Errorf("IsCommon(%q) = true", pw)
		}
	}
	if !IsCommon("123456") {
		t.Error("short 10k entries stay listed for hosts with a lower minimum")
	}
}

func TestIsCommonFindsEveryListedEntry(t *testing.T) {
	list := strings.Split(strings.TrimSuffix(commonList(), "\n"), "\n")
	if len(list) < 500000 {
		t.Fatalf("blocklist has %d entries", len(list))
	}
	for _, pw := range list {
		if !IsCommon(pw) {
			t.Fatalf("IsCommon(%q) = false", pw)
		}
	}
}
