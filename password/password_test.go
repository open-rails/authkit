package password

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
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

func TestVerifyArgon2id_Malformed(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"not-a-phc-string", "not-a-phc-string"},
		{"empty string", ""},
		{"partial prefix", "$argon2id$"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must not panic; result must be false
			match, _ := VerifyArgon2id(tt.encoded, "x")
			if match {
				t.Errorf("VerifyArgon2id(%q, \"x\") returned true; want false", tt.encoded)
			}
		})
	}
}

func TestVerifyBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword failed: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		wantMatch bool
	}{
		{"correct password", "hunter2", true},
		{"wrong password", "wrong", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := VerifyBcrypt(string(hash), tt.password)
			if err != nil {
				t.Fatalf("VerifyBcrypt returned error: %v", err)
			}
			if match != tt.wantMatch {
				t.Errorf("VerifyBcrypt match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestIsBcryptHash(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword failed: %v", err)
	}

	argon2Hash, err := HashArgon2id("some password")
	if err != nil {
		t.Fatalf("HashArgon2id failed: %v", err)
	}

	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"real bcrypt hash", string(bcryptHash), true},
		{"argon2id phc string", argon2Hash, false},
		{"empty string", "", false},
		{"random string", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBcryptHash(tt.hash)
			if got != tt.want {
				t.Errorf("IsBcryptHash(%q) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

func TestValidate_LengthBoundary(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		wantErr     bool
		wantErrMsg  string
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
