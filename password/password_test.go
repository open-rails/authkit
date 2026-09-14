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

func TestValidate_LengthBoundary(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		wantErr    bool
		wantErrMsg string
	}{
		{"7 chars — too short", "1234567", true, "password_too_short"},
		{"8 chars — minimum valid", "12345678", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q) error = %v, wantErr = %v", tt.password, err, tt.wantErr)
			}
			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("Validate(%q) error message = %q, want %q", tt.password, err.Error(), tt.wantErrMsg)
			}
		})
	}
}
