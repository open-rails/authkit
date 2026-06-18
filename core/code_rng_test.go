package core

import (
	"strings"
	"testing"
)

func TestRandInt_RangeAndZeroSafety(t *testing.T) {
	if got := randInt(0); got != 0 {
		t.Fatalf("randInt(0) = %d, want 0", got)
	}
	if got := randInt(-5); got != 0 {
		t.Fatalf("randInt(negative) = %d, want 0", got)
	}
	for i := 0; i < 20000; i++ {
		if v := randInt(10); v < 0 || v > 9 {
			t.Fatalf("randInt(10) out of range: %d", v)
		}
	}
}

// TestRandInt_Unbiased guards against a return of the modulo-bias bug: every
// digit 0..9 must appear with roughly equal frequency over a large sample.
func TestRandInt_Unbiased(t *testing.T) {
	const n = 200000
	var counts [10]int
	for i := 0; i < n; i++ {
		counts[randInt(10)]++
	}
	expected := float64(n) / 10.0
	for d, c := range counts {
		dev := float64(c)/expected - 1.0
		if dev < -0.05 || dev > 0.05 {
			t.Fatalf("digit %d frequency deviates %.3f from uniform (count=%d)", d, dev, c)
		}
	}
}

func TestRandAlphanumeric_LengthAndDigits(t *testing.T) {
	for _, n := range []int{4, 6, 8} {
		code := randAlphanumeric(n)
		if len(code) != n {
			t.Fatalf("randAlphanumeric(%d) length = %d", n, len(code))
		}
		if strings.Trim(code, "0123456789") != "" {
			t.Fatalf("randAlphanumeric(%d) = %q has non-digit chars", n, code)
		}
	}
}
