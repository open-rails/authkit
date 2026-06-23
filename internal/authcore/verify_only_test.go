package authcore

import (
	"context"
	"errors"
	"testing"
)

// #87: a VerifyOnly Service builds with NO active signer (no key discovery),
// rejects every mint path with ErrMissingSigner, and serves an empty JWKS.
// Verification + RBAC reads are unaffected (covered by the DB-backed suites).
// No Postgres required — every mint path checks the signer before touching PG.
func TestVerifyOnlyServiceRejectsMinting(t *testing.T) {
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://verify-only.test",
			IssuedAudiences:   []string{"openrails"},
			ExpectedAudiences: []string{"openrails"},
		},
		Keys: KeysConfig{VerifyOnly: true},
	}, nil)
	if err != nil {
		t.Fatalf("NewFromConfig verify-only: %v", err)
	}
	ctx := context.Background()

	if _, _, err := svc.MintServiceJWT(ctx, ServiceJWTMintOptions{}); !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("MintServiceJWT err=%v, want ErrMissingSigner", err)
	}
	if _, err := svc.MintCustomJWT(ctx, CustomJWTMintOptions{Claims: map[string]any{"k": "v"}}); !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("MintCustomJWT err=%v, want ErrMissingSigner", err)
	}
	if _, err := svc.MintDelegatedAccessToken(ctx, DelegatedAccessParams{}); !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("MintDelegatedAccessToken err=%v, want ErrMissingSigner", err)
	}
	if _, err := svc.MintRemoteApplicationAccessToken(ctx, RemoteApplicationAccessParams{}); !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("MintRemoteApplicationAccessToken err=%v, want ErrMissingSigner", err)
	}

	if jwks := svc.JWKS(); len(jwks.Keys) != 0 {
		t.Fatalf("verify-only JWKS should be empty, got %d keys", len(jwks.Keys))
	}
}
