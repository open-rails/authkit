package authkit

import (
	"errors"
	"testing"
	"time"
)

func TestNamingPolicyNormalization(t *testing.T) {
	ptr := func(d time.Duration) *time.Duration { return &d }
	disabled := false
	cases := []struct {
		name      string
		config    NamingConfig
		enabled   bool
		interval  time.Duration
		mode      FormerNameRetentionMode
		retention time.Duration
		invalid   bool
	}{
		{name: "defaults", enabled: true, interval: 72 * time.Hour, mode: FormerNamesFinite, retention: 2160 * time.Hour},
		{name: "disabled", config: NamingConfig{Enabled: &disabled}, interval: 72 * time.Hour, mode: FormerNamesFinite, retention: 2160 * time.Hour},
		{name: "zero interval", config: NamingConfig{RenameInterval: ptr(0)}, enabled: true, mode: FormerNamesFinite, retention: 2160 * time.Hour},
		{name: "empty retention", config: NamingConfig{FormerNames: FormerNameRetentionConfig{}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesFinite, retention: 2160 * time.Hour},
		{name: "finite omitted duration", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesFinite}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesFinite, retention: 2160 * time.Hour},
		{name: "duration omitted mode", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Duration: ptr(time.Hour)}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesFinite, retention: time.Hour},
		{name: "finite zero", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesFinite, Duration: ptr(0)}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesImmediate},
		{name: "forever", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesForever}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesForever},
		{name: "immediate", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesImmediate}}, enabled: true, interval: 72 * time.Hour, mode: FormerNamesImmediate},
		{name: "negative interval", config: NamingConfig{RenameInterval: ptr(-1)}, invalid: true},
		{name: "negative retention", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Duration: ptr(-1)}}, invalid: true},
		{name: "unknown mode", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: "sometimes"}}, invalid: true},
		{name: "forever and zero", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesForever, Duration: ptr(0)}}, invalid: true},
		{name: "immediate and duration", config: NamingConfig{FormerNames: FormerNameRetentionConfig{Mode: FormerNamesImmediate, Duration: ptr(time.Hour)}}, invalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.config.Normalize()
			if tc.invalid {
				if err == nil {
					t.Fatal("expected invalid policy")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := NamingPolicy{tc.enabled, tc.interval, tc.mode, tc.retention}
			if p != want {
				t.Fatalf("got %+v want %+v", p, want)
			}
		})
	}
}

func TestNamingPolicyExactBoundaries(t *testing.T) {
	p, err := (NamingConfig{}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	last := time.Date(2026, 3, 7, 12, 0, 0, 0, time.FixedZone("before DST", -7*60*60))
	if err := p.CheckRename(nil, last); err != nil {
		t.Fatalf("first rename: %v", err)
	}
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		err := p.CheckRename(&last, last.Add(72*time.Hour+offset))
		if offset < 0 {
			var cooldown *RenameCooldownError
			if !errors.Is(err, ErrRenameRateLimited) || !errors.As(err, &cooldown) || !cooldown.NextRenameAt.Equal(last.Add(72*time.Hour)) {
				t.Fatalf("bad cooldown: %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	expiry := p.FormerNameExpiresAt(last)
	if expiry == nil || !expiry.Equal(last.Add(2160*time.Hour)) {
		t.Fatalf("bad deadline: %v", expiry)
	}
	p.FormerNameRetentionMode = FormerNamesForever
	if p.FormerNameExpiresAt(last) != nil {
		t.Fatal("forever must have no expiry")
	}
	// Already-issued deadlines survive changes to future policy.
	if !expiry.Equal(last.Add(2160 * time.Hour)) {
		t.Fatal("existing deadline changed")
	}
	p.Enabled = false
	if !errors.Is(p.CheckRename(nil, last), ErrRenamesDisabled) {
		t.Fatal("disabled rename accepted")
	}
	p.Enabled = true
	p.RenameInterval = 0
	if err := p.CheckRename(&last, last); err != nil {
		t.Fatal(err)
	}
	p.FormerNameRetentionMode = FormerNamesImmediate
	p.FormerNameRetention = 0
	if !p.FormerNameExpiresAt(last).Equal(last) {
		t.Fatal("immediate is not immediate")
	}
}
