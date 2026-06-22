package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNormalizePreferredLocale(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: " es ", want: "es"},
		{in: "EN-us", want: "en-US"},
		{in: "zh_cn", want: "zh-CN"},
		{in: "es-419", want: "es-419"},
	}
	for _, tt := range tests {
		got, err := NormalizePreferredLocale(tt.in)
		if err != nil {
			t.Fatalf("NormalizePreferredLocale(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizePreferredLocale(%q)=%q, want %q", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"english", "e", "en-US-extra", "en@US"} {
		if _, err := NormalizePreferredLocale(in); err == nil {
			t.Fatalf("NormalizePreferredLocale(%q) expected error", in)
		}
	}
}

func TestSetGetPreferredLocale(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

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

	if err := svc.SetPreferredLocale(ctx, user.ID, "es_419", "explicit"); err != nil {
		t.Fatalf("SetPreferredLocale: %v", err)
	}
	got, err := svc.GetPreferredLocale(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetPreferredLocale: %v", err)
	}
	if got.Locale != "es-419" || got.Source != "explicit" || got.UpdatedAt == nil {
		t.Fatalf("preferred locale = %+v, want es-419 explicit with timestamp", got)
	}
}
