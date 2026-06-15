package core

import "testing"

func TestSecretHashEqual(t *testing.T) {
	a := sha256Hex("123456")
	if !secretHashEqual(a, sha256Hex("123456")) {
		t.Fatal("equal codes should compare equal")
	}
	if secretHashEqual(a, sha256Hex("123457")) {
		t.Fatal("different codes must compare unequal")
	}
	if secretHashEqual(a, "") {
		t.Fatal("empty vs non-empty must be unequal")
	}
	if secretHashEqual("", a) {
		t.Fatal("non-empty vs empty must be unequal")
	}
	if !secretHashEqual("", "") {
		t.Fatal("empty vs empty is equal")
	}
	// Differing length must not match and must not panic.
	if secretHashEqual(a, a[:len(a)-1]) {
		t.Fatal("prefix must not match full digest")
	}
}
