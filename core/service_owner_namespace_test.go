package core

import "testing"

func TestOwnerSlugFromUsername(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "Alice", want: "alice"},
		{in: "alice_1", want: "alice-1"},
		{in: "A__B--C", want: "a-b-c"},
		{in: "---x---", want: "x"},
	}
	for _, tt := range tests {
		got := ownerSlugFromUsername(tt.in)
		if got != tt.want {
			t.Fatalf("ownerSlugFromUsername(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}
