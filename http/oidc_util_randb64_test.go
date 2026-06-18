package authhttp

import "testing"

func TestRandB64_LengthAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		v := randB64(32)
		if v == "" {
			t.Fatal("randB64 returned empty string")
		}
		// 32 raw bytes -> 43 base64url chars (no padding).
		if len(v) != 43 {
			t.Fatalf("unexpected length %d for 32-byte token: %q", len(v), v)
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("randB64 produced a duplicate value: %q", v)
		}
		seen[v] = struct{}{}
	}
}

func TestRandB64_AllZeroIsImpossibleInPractice(t *testing.T) {
	// A zero-filled 32-byte token would base64url-encode to 43 'A's; the old
	// error-ignoring implementation could emit exactly this on RNG failure.
	const allZero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if got := randB64(32); got == allZero {
		t.Fatalf("randB64 returned the all-zero token")
	}
}
