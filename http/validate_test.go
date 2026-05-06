package authhttp

import "testing"

func TestValidateUsername_DoesNotHardcodeReservedList(t *testing.T) {
	t.Parallel()

	cases := []string{
		"admin",
		"root",
		"sudo",
		"superuser",
		"SuperUser",
	}
	for _, username := range cases {
		username := username
		t.Run(username, func(t *testing.T) {
			t.Parallel()
			if err := validateUsername(username); err != nil {
				t.Fatalf("expected syntax validation to pass for %q, got %v", username, err)
			}
		})
	}
}
