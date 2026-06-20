package authhttp

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

type delegatedTestRemoteApplicationSource struct {
	app        core.RemoteApplication
	permission []string
	membership []core.OrgMembership
}

func newDelegatedAuthorityTestVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string, permissions []string) *Verifier {
	t.Helper()
	v := NewVerifier(WithOrgMode("multi"))
	v.fedSource = &delegatedTestRemoteApplicationSource{
		app: core.RemoteApplication{
			ID:      "remote-app-1",
			Slug:    "remote-app",
			Issuer:  iss,
			Enabled: true,
		},
		permission: permissions,
	}
	if err := v.AddIssuer(iss, aud, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatalf("AddIssuer: %v", err)
	}
	return v
}

func newDelegatedTestVerifier(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) *Verifier {
	t.Helper()
	return newDelegatedAuthorityTestVerifier(t, signer, iss, aud, []string{"openrails:*", "tensorhub:*", "platform:*"})
}

func (s *delegatedTestRemoteApplicationSource) ListRemoteApplications(ctx context.Context, enabledOnly bool) ([]core.RemoteApplication, error) {
	if enabledOnly && !s.app.Enabled {
		return nil, nil
	}
	return []core.RemoteApplication{s.app}, nil
}

func (s *delegatedTestRemoteApplicationSource) GetRemoteApplication(ctx context.Context, issuer string) (*core.RemoteApplication, error) {
	if issuer != s.app.Issuer {
		return nil, errors.New("not_found")
	}
	return &s.app, nil
}

func (s *delegatedTestRemoteApplicationSource) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]core.OrgMembership, []string, error) {
	if appID != s.app.ID {
		return nil, nil, errors.New("not_found")
	}
	return s.membership, s.permission, nil
}

func TestMintAndVerifyDelegatedAccessTokenBasic(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	iss := "https://cozy.example"
	aud := []string{"tensorhub"}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "user-123",
		Attributes:       map[string]any{"tier": "cozy_free"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cl, err := newDelegatedTestVerifier(t, signer, iss, aud).Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "" {
		t.Fatalf("expected empty UserID (no sub), got %q", cl.UserID)
	}
	if !cl.IsDelegated() {
		t.Fatal("expected IsDelegated")
	}
	dp, ok := cl.Delegated()
	if !ok {
		t.Fatal("Delegated() returned !ok")
	}
	if dp.DelegatedSubject != "user-123" || dp.UserTier != "cozy_free" {
		t.Fatalf("principal=%+v", dp)
	}
}

func TestVerifyRejectsBothSubAndDelegatedSub(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "platform-kid")
	iss := "https://cozy.example"
	now := time.Now()
	tok, err := signer.Sign(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"sub":           "local-1",
		"delegated_sub": "ext-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "conflicting_subject" {
		t.Fatalf("expected conflicting_subject, got %v", err)
	}
}

func TestMintRequiresDelegatedSubject(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	if _, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{Issuer: "x"}); err == nil {
		t.Fatal("expected error for missing delegated_sub")
	}
}

func TestNativeTokenIsNotDelegated(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	}, map[string]any{"typ": AccessTokenType})
	cl, err := newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if cl.IsDelegated() {
		t.Fatal("native token should not be delegated")
	}
	if cl.UserID != "local-1" {
		t.Fatalf("UserID=%q", cl.UserID)
	}
}

func TestVerifyRejectsAccessTokenWithoutAccessTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.Sign(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"tensorhub"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
		"sub": "local-1",
	})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "access_token_wrong_typ" {
		t.Fatalf("expected access_token_wrong_typ, got %v", err)
	}
}

func TestVerifyRejectsDelegatedSubWithoutDelegatedTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss":           iss,
		"aud":           []string{"tensorhub"},
		"iat":           now.Unix(),
		"exp":           now.Add(time.Minute).Unix(),
		"delegated_sub": "ext-1",
	}, map[string]any{"typ": AccessTokenType})
	_, err := newDelegatedTestVerifier(t, signer, iss, []string{"tensorhub"}).Verify(tok)
	if err == nil || err.Error() != "delegated_access_wrong_typ" {
		t.Fatalf("expected delegated_access_wrong_typ, got %v", err)
	}
}

func TestVerifyRejectsRemoteApplicationAccessTokenWithWrongTyp(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	iss := "https://cozy.example"
	now := time.Now()
	tok, err := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": iss,
		"aud": []string{"openrails"},
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	}, map[string]any{"typ": "service+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newDelegatedTestVerifier(t, signer, iss, []string{"openrails"}).Verify(tok)
	if err == nil || err.Error() != "unsupported_token_typ" {
		t.Fatalf("expected unsupported_token_typ, got %v", err)
	}
}
