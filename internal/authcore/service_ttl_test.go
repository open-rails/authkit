package authcore

import (
	"testing"
	"time"
)

func TestNewFromConfigDefaultAccessTokenTTLIsFifteenMinutes(t *testing.T) {
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{VerifyOnly: true},
	}, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if got := svc.Config().Token.AccessTokenDuration; got != 15*time.Minute {
		t.Fatalf("default access token TTL = %v, want 15m", got)
	}
}
