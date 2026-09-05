package authhttp

// #261 unit matrices for the request-time clamps. The boot-time triple
// validation lives in embedded (normalizeDelegatedConfig); these
// cover the per-request mechanics: audience-subset clamp and TTL clamp.

import (
	"context"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func TestResolveDelegatedAudiences(t *testing.T) {
	allowed := []string{"tensorhub.net", "other.example"}
	tests := []struct {
		name      string
		requested []string
		want      []string
		wantErr   bool
	}{
		{name: "empty request mints the full allowlist", requested: nil, want: allowed},
		{name: "subset", requested: []string{"tensorhub.net"}, want: []string{"tensorhub.net"}},
		{name: "trim and dedup", requested: []string{" tensorhub.net ", "tensorhub.net"}, want: []string{"tensorhub.net"}},
		{name: "full set explicitly", requested: []string{"other.example", "tensorhub.net"}, want: []string{"other.example", "tensorhub.net"}},
		{name: "outside the allowlist", requested: []string{"evil.example"}, wantErr: true},
		{name: "mixed valid and invalid rejects the whole request", requested: []string{"tensorhub.net", "evil.example"}, wantErr: true},
		{name: "blank-only request", requested: []string{" ", ""}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDelegatedAudiences(allowed, tt.requested)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestClampDelegatedTTL(t *testing.T) {
	cfg := embedded.DelegatedConfig{
		TTLFloor:   time.Minute,
		TTLDefault: 15 * time.Minute,
		TTLCeiling: time.Hour,
	}
	tests := []struct {
		name      string
		requested int
		want      time.Duration
	}{
		{"absent mints the default", 0, 15 * time.Minute},
		{"negative mints the default", -5, 15 * time.Minute},
		{"below floor clamps up", 1, time.Minute},
		{"at floor", 60, time.Minute},
		{"in range passes through", 600, 10 * time.Minute},
		{"at ceiling", 3600, time.Hour},
		{"above ceiling clamps down", 86400, time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, clampDelegatedTTL(cfg, tt.requested))
		})
	}
}

func TestDelegatedTokenSigningKID(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "mint-kid")
	require.NoError(t, err)
	token, err := signer.Sign(context.Background(), jwt.MapClaims{"iss": "x"})
	require.NoError(t, err)
	kid, err := delegatedTokenSigningKID(token)
	require.NoError(t, err)
	require.Equal(t, "mint-kid", kid)

	for _, bad := range []string{"", "not-a-jwt", "a.b", "!!!.e30.sig"} {
		_, err := delegatedTokenSigningKID(bad)
		require.Error(t, err, "input %q", bad)
	}
}
