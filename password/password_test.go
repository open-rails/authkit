package password

import (
	"errors"
	"strings"
	"testing"
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

func TestPolicyValidateCountsCharacters(t *testing.T) {
	p, err := Policy{MinLength: 4, MaxLength: 6, AllowCommon: true}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	for pw, want := range map[string]error{
		"abc": ErrTooShort, "abcd": nil, "ééé": ErrTooShort, "éééé": nil,
		"😀😀😀😀😀😀": nil, "abcdefg": ErrTooLong,
	} {
		if got := p.Validate(pw); got != want {
			t.Errorf("Validate(%q) = %v, want %v", pw, got, want)
		}
	}
}

func TestPolicyNormalize(t *testing.T) {
	if p, err := (Policy{}).Normalize(); err != nil || p != (Policy{MinLength: DefaultMinLength, MaxLength: DefaultMaxLength}) {
		t.Fatalf("default = %+v, %v", p, err)
	}
	if p, err := (Policy{MinLength: 200}).Normalize(); err != nil || p.MaxLength != 200 {
		t.Fatalf("min above default max = %+v, %v", p, err)
	}
	for _, bad := range []Policy{{MinLength: -1}, {MinLength: 10, MaxLength: 9}, {MaxLength: MaxLengthCeiling + 1}} {
		if _, err := bad.Normalize(); err == nil {
			t.Errorf("Normalize(%+v) accepted", bad)
		}
	}
}

func TestPolicyRejectsCommonIdentifiersAndMissingClasses(t *testing.T) {
	p, _ := Policy{}.Normalize()
	if err := p.Validate("QwertyUIOP"); err != ErrTooCommon {
		t.Fatalf("common = %v", err)
	}
	if err := p.Validate("xx-Alice-xx", "alice"); err != ErrContainsIdentifier {
		t.Fatalf("identifier = %v", err)
	}
	if err := p.Validate("abc-12345", "abc"); err != nil {
		t.Fatalf("short identifiers are ignored: %v", err)
	}
	if err := (Policy{AllowCommon: true, MinLength: 8, MaxLength: 128}).Validate("qwertyuiop"); err != nil {
		t.Fatalf("AllowCommon = %v", err)
	}
	strict, _ := Policy{RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSymbol: true}.Normalize()
	var unmet *RequirementsError
	if err := strict.Validate("ÉCOLE-DE-NUIT"); !errors.As(err, &unmet) || strings.Join(unmet.Missing, ",") != "lowercase,digit" {
		t.Fatalf("missing = %v", err)
	}
	if err := strict.Validate("Écoledenuit7 "); err != nil {
		t.Fatalf("a space is a symbol: %v", err)
	}
}

func TestBlocklistCoversCommonLongPasswords(t *testing.T) {
	p, _ := Policy{}.Normalize()
	for _, pw := range []string{"password123", "Password1!", "qwerty12345", "iloveyou123", "PASSWORD", "qwertyuiop"} {
		if err := p.Validate(pw); err != ErrTooCommon {
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
