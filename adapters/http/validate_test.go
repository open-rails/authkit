package authhttp

import "testing"

func TestValidateUsername_Reserved(t *testing.T) {
	t.Parallel()

	cases := []string{
		"admin",
		"moderator",
		"root",
		"sudo",
		"superuser",
		"SuperUser",
	}
	for _, username := range cases {
		username := username
		t.Run(username, func(t *testing.T) {
			t.Parallel()
			if err := validateUsername(username); err == nil || err.Error() != "username_reserved" {
				t.Fatalf("expected username_reserved for %q, got %v", username, err)
			}
		})
	}
}
