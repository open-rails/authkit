package authflow_test

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/authflow"
)

func TestRecentSignInClockSkew(t *testing.T) {
	now := time.Date(2026, time.October, 18, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name     string
		authTime time.Time
		want     bool
	}{
		{"missing authentication time", time.Time{}, false},
		{"current authentication", now, true},
		{"recent authentication", now.Add(-time.Minute), true},
		{"exact freshness boundary", now.Add(-15 * time.Minute), true},
		{"past freshness boundary", now.Add(-15*time.Minute - time.Nanosecond), false},
		{"one nanosecond ahead", now.Add(time.Nanosecond), true},
		{"one second ahead", now.Add(time.Second), true},
		{"exact skew boundary", now.Add(5 * time.Second), true},
		{"past skew boundary", now.Add(5*time.Second + time.Nanosecond), false},
		{"far future authentication", now.Add(time.Minute), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := authflow.RecentSignIn(tt.authTime, nil, false, now); got != tt.want {
				t.Fatalf("RecentSignIn(authTime=%s, now=%s) = %v, want %v", tt.authTime, now, got, tt.want)
			}
		})
	}
}

func TestRecentSignInRequiresMFA(t *testing.T) {
	now := time.Date(2026, time.October, 18, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name string
		amr  []string
		mfa  bool
		want bool
	}{
		{"no enrolled second factor", nil, false, true},
		{"missing second factor proof", nil, true, false},
		{"password is not a second factor", []string{"pwd"}, true, false},
		{"OTP proof", []string{"pwd", "otp"}, true, true},
		{"MFA proof", []string{"mfa"}, true, true},
		{"normalized MFA proof", []string{"pwd", " OTP "}, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, offset := range []time.Duration{0, time.Second, 5 * time.Second} {
				if got := authflow.RecentSignIn(now.Add(offset), tt.amr, tt.mfa, now); got != tt.want {
					t.Fatalf("RecentSignIn(offset=%s, amr=%v, mfa=%v) = %v, want %v", offset, tt.amr, tt.mfa, got, tt.want)
				}
			}
		})
	}
}
