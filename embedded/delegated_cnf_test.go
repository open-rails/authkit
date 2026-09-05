package embedded

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
)

// ak#277: ConfirmationCertificateSHA256 mints exactly {"cnf":{"x5t#S256":..}};
// nil keeps the trusted in-process token unbound.
func TestServiceMintDelegatedCertificateBound(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)
	sum := jwtkit.CertificateSHA256([]byte("delegate-leaf-der"))

	bound, err := svc.MintDelegatedAccessToken(context.Background(), DelegatedAccessParams{
		Audiences: []string{"tensorhub"}, DelegatedSubject: "user-123", ConfirmationCertificateSHA256: &sum,
	})
	if err != nil {
		t.Fatalf("bound mint: %v", err)
	}
	cnf, ok := verifyAgainstServiceJWKS(t, svc, bound)["cnf"].(map[string]any)
	if !ok || len(cnf) != 1 || cnf["x5t#S256"] != jwtkit.CertificateThumbprint(sum) {
		t.Fatalf("cnf = %#v", cnf)
	}

	unbound, err := svc.MintDelegatedAccessToken(context.Background(), DelegatedAccessParams{
		Audiences: []string{"tensorhub"}, DelegatedSubject: "user-123",
	})
	if err != nil {
		t.Fatalf("unbound mint: %v", err)
	}
	if _, has := verifyAgainstServiceJWKS(t, svc, unbound)["cnf"]; has {
		t.Fatal("unbound token carries cnf")
	}
}
