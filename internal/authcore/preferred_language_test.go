package authcore

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNormalizePreferredLanguage(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: " es ", want: "es"},
		{in: "EN", want: "en"},
		{in: "zh", want: "zh"},
	}
	for _, tt := range tests {
		got, err := NormalizePreferredLanguage(tt.in)
		if err != nil {
			t.Fatalf("NormalizePreferredLanguage(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizePreferredLanguage(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"english", "e", "en-US", "zh_cn", "es-419", "en@US"} {
		if _, err := NormalizePreferredLanguage(in); err == nil {
			t.Fatalf("NormalizePreferredLanguage(%q) expected error", in)
		}
	}
}

func TestSetGetPreferredLanguage(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	username := "pl" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username) })

	user, err := svc.ImportUser(ctx, ImportUserInput{
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("ImportUser: %v", err)
	}

	if err := svc.SetPreferredLanguage(ctx, user.ID, "es"); err != nil {
		t.Fatalf("SetPreferredLanguage: %v", err)
	}
	got, err := svc.GetPreferredLanguage(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPreferredLanguage: %v", err)
	}
	if got.Language != "es" {
		t.Fatalf("preferred language = %+v, want es", got)
	}
}
