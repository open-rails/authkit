package authcore

// #261 boot-refusal matrix: an impossible Delegated TTL triple never boots and
// is never silently clamped; unset fields take the documented defaults.

import (
	"testing"
	"time"
)

func TestNormalizeDelegatedConfig(t *testing.T) {
	tests := []struct {
		name    string
		in      DelegatedConfig
		wantErr bool
		want    DelegatedConfig
	}{
		{
			name: "zero value stays disabled",
			in:   DelegatedConfig{},
			want: DelegatedConfig{},
		},
		{
			name:    "TTLs without audiences are dead config",
			in:      DelegatedConfig{TTLDefault: time.Minute},
			wantErr: true,
		},
		{
			name: "audiences only takes all defaults",
			in:   DelegatedConfig{Audiences: []string{" tensorhub.net ", "tensorhub.net", ""}},
			want: DelegatedConfig{
				Audiences:  []string{"tensorhub.net"},
				TTLFloor:   DefaultDelegatedTTLFloor,
				TTLDefault: DefaultDelegatedTTLDefault,
				TTLCeiling: DefaultDelegatedTTLCeiling,
			},
		},
		{
			name: "explicit consistent triple",
			in: DelegatedConfig{
				Audiences: []string{"a"}, TTLFloor: 30 * time.Second,
				TTLDefault: 10 * time.Minute, TTLCeiling: 30 * time.Minute,
			},
			want: DelegatedConfig{
				Audiences: []string{"a"}, TTLFloor: 30 * time.Second,
				TTLDefault: 10 * time.Minute, TTLCeiling: 30 * time.Minute,
			},
		},
		{
			name:    "negative TTL",
			in:      DelegatedConfig{Audiences: []string{"a"}, TTLFloor: -time.Second},
			wantErr: true,
		},
		{
			name:    "floor above ceiling",
			in:      DelegatedConfig{Audiences: []string{"a"}, TTLFloor: 2 * time.Hour},
			wantErr: true,
		},
		{
			name:    "default below floor",
			in:      DelegatedConfig{Audiences: []string{"a"}, TTLDefault: time.Second},
			wantErr: true,
		},
		{
			name:    "default above ceiling",
			in:      DelegatedConfig{Audiences: []string{"a"}, TTLDefault: 45 * time.Minute, TTLCeiling: 30 * time.Minute},
			wantErr: true,
		},
		{
			name: "default default (15m) above explicit low ceiling refuses, never clamps",
			in:   DelegatedConfig{Audiences: []string{"a"}, TTLCeiling: 5 * time.Minute},
			// cozy-art's platform_signer silently clamped defaultTTL to maxTTL
			// here; the AuthKit port refuses instead (env-doctrine house style).
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeDelegatedConfig(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want boot refusal, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.TTLFloor != tt.want.TTLFloor || got.TTLDefault != tt.want.TTLDefault || got.TTLCeiling != tt.want.TTLCeiling {
				t.Fatalf("ttls = %+v, want %+v", got, tt.want)
			}
			if len(got.Audiences) != len(tt.want.Audiences) {
				t.Fatalf("audiences = %v, want %v", got.Audiences, tt.want.Audiences)
			}
			for i := range got.Audiences {
				if got.Audiences[i] != tt.want.Audiences[i] {
					t.Fatalf("audiences = %v, want %v", got.Audiences, tt.want.Audiences)
				}
			}
		})
	}
}

// The refusal must fire on the real construction path, not just the helper.
func TestNewFromConfigRefusesInvalidDelegatedTriple(t *testing.T) {
	cfg := Config{
		Token: TokenConfig{Issuer: "https://issuer.example", IssuedAudiences: []string{"app"}},
		Keys:  KeysConfig{VerifyOnly: true},
		Delegated: DelegatedConfig{
			Audiences: []string{"tensorhub.net"},
			TTLFloor:  time.Hour, TTLCeiling: time.Minute,
		},
	}
	if _, err := NewFromConfig(cfg, nil); err == nil {
		t.Fatal("want construction refusal for floor > ceiling")
	}
	cfg.Delegated = DelegatedConfig{Audiences: []string{"tensorhub.net"}}
	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Config().Delegated; got.TTLDefault != DefaultDelegatedTTLDefault {
		t.Fatalf("normalized Delegated = %+v", got)
	}
}
