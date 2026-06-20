package core

import (
	"testing"
	"time"
)

func TestNewFromConfigDefaultAccessTokenTTLIsFifteenMinutes(t *testing.T) {
	svc, err := NewFromConfig(Config{
		Issuer:            "https://example.com",
		IssuedAudiences:   []string{"app"},
		ExpectedAudiences: []string{"app"},
		VerifyOnly:        true,
	})
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if got := svc.Options().AccessTokenDuration; got != 15*time.Minute {
		t.Fatalf("default access token TTL = %v, want 15m", got)
	}
}
