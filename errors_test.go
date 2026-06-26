package authkit

import (
	"errors"
	"testing"
)

func TestErrorForCode(t *testing.T) {
	// Every sentinel round-trips through its wire code.
	for code, want := range errorsByCode {
		if got := ErrorForCode(code); !errors.Is(got, want) {
			t.Errorf("ErrorForCode(%q) = %v, want %v", code, got, want)
		}
	}
	// Uniqueness: no two sentinels collapsed onto one code. The var block in
	// errors.go currently defines 47 sentinels — bump this if you add one.
	if len(errorsByCode) != 47 {
		t.Fatalf("registry has %d codes; a duplicate code (or a new sentinel) shifts this — see errors.go", len(errorsByCode))
	}
	// Unknown / empty codes resolve to nil so callers can fall back.
	if ErrorForCode("") != nil || ErrorForCode("no_such_code") != nil {
		t.Error("ErrorForCode should return nil for unknown codes")
	}
	// The named wart is now a clean snake_case wire code.
	if ErrGroupNotFound.Error() != "permission_group_not_found" {
		t.Errorf("ErrGroupNotFound code = %q, want permission_group_not_found", ErrGroupNotFound.Error())
	}
}
