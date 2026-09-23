package password

import (
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
	p, err := Policy{MinLength: 4, MaxLength: 6}.Normalize()
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
	if p, err := (Policy{}).Normalize(); err != nil || p != (Policy{DefaultMinLength, DefaultMaxLength}) {
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
