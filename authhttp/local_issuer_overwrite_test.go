package authhttp

// AK-AUTH-01: a federated (remote_application) registration must never overwrite
// the trusted local issuer entry. AddIssuer keys issuers by string and upserts by
// issuer, so without this guard a remote_application registered under the
// platform's own issuer would swap the platform's signing keys — breaking
// verification of all first-party tokens (auth DoS) and binding the platform
// issuer identity to attacker key material.

import (
	"crypto"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
)

// mintAccessJWT builds a standard first-party access token (iss/aud/sub/iat/exp,
// typ=access+jwt via signToken) signed by signer, for the AK-AUTH-01 guard tests.
// Audience is "platform" to match the issuer registered by these tests. extra
// claims, when non-nil, override/augment the baseline set.
func mintAccessJWT(t *testing.T, signer jwtkit.Signer, issuer string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": issuer,
		"aud": "platform",
		"sub": "user-1",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signToken(t, signer, claims)
}

// TestAddIssuerRefusesToOverwriteLocalWithFederated is the verifier-layer guard:
// once an issuer is registered as local, a non-local AddIssuer for the same
// issuer string must be rejected and must not replace the cached keys.
func TestAddIssuerRefusesToOverwriteLocalWithFederated(t *testing.T) {
	platformSigner, _ := jwtkit.NewRSASigner(2048, "platform-kid")
	attackerSigner, _ := jwtkit.NewRSASigner(2048, "attacker-kid")

	platformIss := "https://platform.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	if err := ver.AddIssuer(platformIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{platformSigner.KID(): platformSigner.PublicKey()},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("register local platform issuer: %v", err)
	}

	// Attacker attempts to overwrite the local entry under the same issuer string
	// with their own key and IsLocal=false (the only way a remote_application is
	// registered). This must be refused.
	err := ver.AddIssuer(platformIss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{attackerSigner.KID(): attackerSigner.PublicKey()},
		// IsLocal omitted (false) — federated registration
	})
	if err == nil {
		t.Fatal("AK-AUTH-01: AddIssuer allowed a federated registration to overwrite the local issuer")
	}

	// The platform's real token must still verify — keys were not swapped.
	platformTok := mintAccessJWT(t, platformSigner, platformIss, nil)
	if _, verr := ver.Verify(platformTok); verr != nil {
		t.Fatalf("AK-AUTH-01: platform token no longer verifies after attempted overwrite: %v", verr)
	}

	// A token signed by the attacker's key under the platform issuer must NOT
	// verify — the attacker key was never cached for the platform issuer.
	attackerTok := mintAccessJWT(t, attackerSigner, platformIss, nil)
	if _, verr := ver.Verify(attackerTok); verr == nil {
		t.Fatal("AK-AUTH-01: token signed with attacker key verified under the platform issuer — keys were swapped")
	}
}

// TestAddIssuerAllowsLocalRefresh ensures the guard does not break the legitimate
// path: the local issuer can still be re-registered (key rotation / refresh).
func TestAddIssuerAllowsLocalRefresh(t *testing.T) {
	signerA, _ := jwtkit.NewRSASigner(2048, "kid-a")
	signerB, _ := jwtkit.NewRSASigner(2048, "kid-b")
	iss := "https://platform.example"

	ver := NewVerifier(WithAlgorithms("RS256"))
	if err := ver.AddIssuer(iss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signerA.KID(): signerA.PublicKey()},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("register local issuer: %v", err)
	}
	// Re-register the local issuer (local→local) with an additional rotated key.
	if err := ver.AddIssuer(iss, []string{"platform"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{
			signerA.KID(): signerA.PublicKey(),
			signerB.KID(): signerB.PublicKey(),
		},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("AK-AUTH-01 guard wrongly blocked a local issuer refresh: %v", err)
	}
	tok := mintAccessJWT(t, signerB, iss, nil)
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("rotated local key does not verify after refresh: %v", err)
	}
}
