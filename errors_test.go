package authkit

import (
	"errors"
	"fmt"
	"net/http"
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
	// errors.go currently defines 56 sentinels — bump this if you add one.
	if len(errorsByCode) != 56 {
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

// TestCodeForError covers the #197 fix: exposed Client methods return WRAPPED
// sentinels, so keying off err.Error() (as the server used to) misses them. Chain-
// aware CodeForError must still resolve the sentinel's wire code — otherwise the
// server emits a 500 and the remote client loses errors.Is identity across the wire.
func TestCodeForError(t *testing.T) {
	// The shape an exposed method actually returns, e.g.
	// fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, cause). err.Error() is no longer
	// the bare wire code, so ErrorForCode(err.Error()) would return "".
	wrapped := fmt.Errorf("%w: smtp: connection refused", ErrEmailDeliveryFailed)

	// Sanity: the naive lookup the server used to do is now a miss — this is the bug.
	if ErrorForCode(wrapped.Error()) != nil {
		t.Fatalf("precondition: wrapped err.Error() %q should not be a bare registry key", wrapped.Error())
	}

	// CodeForError resolves the wrapped sentinel to the right wire code.
	code := CodeForError(wrapped)
	if want := ErrEmailDeliveryFailed.Error(); code != want {
		t.Fatalf("CodeForError(wrapped) = %q, want %q", code, want)
	}

	// Round-trip: the emitted code re-derives the sentinel on the remote side, and
	// errors.Is identity survives the hop — the whole point of the wire contract.
	if got := ErrorForCode(code); !errors.Is(got, ErrEmailDeliveryFailed) {
		t.Errorf("ErrorForCode(%q) = %v, does not round-trip to ErrEmailDeliveryFailed", code, got)
	}
	if !errors.Is(wrapped, ErrEmailDeliveryFailed) {
		t.Error("wrapped error lost errors.Is(ErrEmailDeliveryFailed) identity")
	}

	// server.statusFor returns 422 exactly when CodeForError(err) != "" and 500
	// otherwise. A resolvable (wrapped) sentinel is a client condition (422), not a
	// server fault (500). statusFor lives in package server; this asserts the exact
	// predicate it keys off, which errors_test.go can reach without importing server.
	status := http.StatusInternalServerError
	if CodeForError(wrapped) != "" {
		status = http.StatusUnprocessableEntity
	}
	if status != http.StatusUnprocessableEntity {
		t.Errorf("wrapped sentinel maps to HTTP %d, want %d (422)", status, http.StatusUnprocessableEntity)
	}

	// Nil and non-sentinel errors resolve to "" so the server falls back to 500.
	if CodeForError(nil) != "" {
		t.Error("CodeForError(nil) should be empty")
	}
	if CodeForError(errors.New("some opaque failure")) != "" {
		t.Error("CodeForError(non-sentinel) should be empty")
	}
}
