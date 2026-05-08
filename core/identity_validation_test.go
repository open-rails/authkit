package core

import "testing"

func TestValidateUsernameCanonicalPolicy(t *testing.T) {
	tests := []struct {
		username string
		wantCode string
	}{
		{username: "abc", wantCode: ErrCodeUsernameTooShort},
		{username: "1abcd", wantCode: ErrCodeUsernameMustStartWithLetter},
		{username: "abcd-ef", wantCode: ErrCodeUsernameInvalidCharacters},
		{username: "user@example", wantCode: ErrCodeUsernameCannotContainAt},
		{username: "+user", wantCode: ErrCodeUsernameMustStartWithLetter},
		{username: "valid_user1", wantCode: ""},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("ValidateUsername() err=%v", err)
				}
				return
			}
			if got := ValidationErrorCode(err); got != tt.wantCode {
				t.Fatalf("ValidateUsername() code=%q want %q err=%v", got, tt.wantCode, err)
			}
		})
	}
}

func TestOwnerSlugFromUsernameCanonicalPolicy(t *testing.T) {
	if got := OwnerSlugFromUsername("Fidika_Art"); got != "fidika-art" {
		t.Fatalf("OwnerSlugFromUsername()=%q", got)
	}
}

func TestValidateEmailCanonicalPolicy(t *testing.T) {
	if got := NormalizeEmail(" USER@Example.COM "); got != "user@example.com" {
		t.Fatalf("NormalizeEmail()=%q", got)
	}
	for _, email := range []string{"", "no-at", "a@", "@example.com", "a@example", "a@.example.com"} {
		if got := ValidationErrorCode(ValidateEmail(email)); got != ErrCodeInvalidEmail {
			t.Fatalf("ValidateEmail(%q) code=%q", email, got)
		}
	}
	if err := ValidateEmail("user@example.com"); err != nil {
		t.Fatalf("ValidateEmail(valid) err=%v", err)
	}
}

func TestValidatePhoneCanonicalPolicy(t *testing.T) {
	if got := NormalizePhone(" +15551234567 "); got != "+15551234567" {
		t.Fatalf("NormalizePhone()=%q", got)
	}
	for _, phone := range []string{"", "15551234567", "+05551234567", "+1abc", "+1234567890123456"} {
		if got := ValidationErrorCode(ValidatePhone(phone)); got != ErrCodeInvalidPhoneNumber {
			t.Fatalf("ValidatePhone(%q) code=%q", phone, got)
		}
	}
	if err := ValidatePhone("+15551234567"); err != nil {
		t.Fatalf("ValidatePhone(valid) err=%v", err)
	}
}

func TestValidatePasswordCanonicalPolicy(t *testing.T) {
	if got := ValidationErrorCode(ValidatePassword("short")); got != ErrCodePasswordTooShort {
		t.Fatalf("ValidatePassword(short) code=%q", got)
	}
	if err := ValidatePassword("long-enough"); err != nil {
		t.Fatalf("ValidatePassword(valid) err=%v", err)
	}
}
