package core

import "testing"

func TestIsReservedUsername(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		username string
		want     bool
	}{
		{name: "admin", username: "admin", want: true},
		{name: "moderator", username: "moderator", want: true},
		{name: "root", username: "root", want: true},
		{name: "sudo", username: "sudo", want: true},
		{name: "superuser", username: "superuser", want: true},
		{name: "case-insensitive", username: "SuperUser", want: true},
		{name: "trimmed", username: "  admin  ", want: true},
		{name: "non-reserved", username: "alice", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsReservedUsername(tc.username)
			if got != tc.want {
				t.Fatalf("IsReservedUsername(%q) = %v, want %v", tc.username, got, tc.want)
			}
		})
	}
}
