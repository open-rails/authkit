package authhttp

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
)

func TestDelegatedDocumentsFederatedContract(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "issuer-kid")
	issuer := "https://site-a.example"
	service := authcore.NewService(embedded.Config{Token: embedded.TokenConfig{Issuer: issuer}}, authcore.Keyset{
		Active: signer, PublicKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	})
	references := map[string]string{
		"example.entitlements/v1": documents.Digest([]byte("entitlements")),
		"example.catalog/v2":      documents.Digest([]byte("catalog")),
	}
	token, err := service.MintDelegatedAccessToken(context.Background(), authkit.DelegatedAccessParams{
		Audiences: []string{"resource-b"}, DelegatedSubject: "external-user", Documents: references, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawClaims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, rawClaims); err != nil {
		t.Fatal(err)
	}
	if rawDocuments, ok := rawClaims["documents"].(map[string]any); !ok || len(rawDocuments) != len(references) {
		t.Fatalf("top-level documents wire claim = %#v", rawClaims["documents"])
	}
	if attributes, ok := rawClaims["attributes"].(map[string]any); ok {
		if _, shadowed := attributes["documents"]; shadowed {
			t.Fatal("documents claim was nested under attributes")
		}
	}
	claims, principal, err := newDelegatedVerifier(t, signer, issuer, []string{"resource-b"}).VerifyDelegatedAccess(token)
	if err != nil {
		t.Fatal(err)
	}
	for documentType, digest := range references {
		fromClaims, ok := claims.DocumentReference(documentType)
		if !ok || fromClaims.Digest != digest {
			t.Fatalf("claims reference %q = %+v, %v", documentType, fromClaims, ok)
		}
		fromPrincipal, ok := principal.DocumentReference(documentType)
		if !ok || fromPrincipal != fromClaims {
			t.Fatalf("principal reference %q = %+v, %v", documentType, fromPrincipal, ok)
		}
	}

	legacyToken, err := service.MintDelegatedAccessToken(context.Background(), authkit.DelegatedAccessParams{
		Audiences: []string{"resource-b"}, DelegatedSubject: "without-documents", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyClaims, err := newDelegatedVerifier(t, signer, issuer, []string{"resource-b"}).Verify(legacyToken)
	if err != nil || legacyClaims.Documents != nil {
		t.Fatalf("token without documents = %v, %v", legacyClaims.Documents, err)
	}
}

func TestDelegatedDocumentsRejectMalformedDuplicateAndOversizedClaims(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid")
	issuer := "https://site-a.example"
	base := authkit.DelegatedAccessParams{Issuer: issuer, Audiences: []string{"resource-b"}, DelegatedSubject: "external-user"}

	bad := base
	bad.Documents = map[string]string{"unversioned": documents.Digest([]byte("x"))}
	if _, err := authcore.MintDelegatedAccessToken(context.Background(), signer, bad); !errors.Is(err, documents.ErrInvalidReference) {
		t.Fatalf("bad type = %v", err)
	}
	bad = base
	bad.Attributes = map[string]any{"documents": map[string]string{"example.entitlements/v1": documents.Digest([]byte("x"))}}
	if _, err := authcore.MintDelegatedAccessToken(context.Background(), signer, bad); !errors.Is(err, documents.ErrReservedAttribute) {
		t.Fatalf("shadowing attribute = %v", err)
	}
	bad = base
	bad.Documents = map[string]string{}
	for i := 0; i <= documents.MaxReferences; i++ {
		bad.Documents[fmt.Sprintf("example.type%d/v1", i)] = documents.Digest([]byte(fmt.Sprint(i)))
	}
	if _, err := authcore.MintDelegatedAccessToken(context.Background(), signer, bad); !errors.Is(err, documents.ErrTooManyReferences) {
		t.Fatalf("too many mint references = %v", err)
	}
	bad = base
	bad.Documents = map[string]string{}
	for i := 0; i < documents.MaxReferences; i++ {
		bad.Documents[strings.Repeat("a", 230)+fmt.Sprint(i)+"/v1"] = documents.Digest([]byte(fmt.Sprint(i)))
	}
	if _, err := authcore.MintDelegatedAccessToken(context.Background(), signer, bad); !errors.Is(err, documents.ErrReferencesTooLarge) {
		t.Fatalf("oversized mint references = %v", err)
	}

	now := time.Now()
	verifier := newDelegatedVerifier(t, signer, issuer, []string{"resource-b"})
	malformed, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": issuer, "aud": []string{"resource-b"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"delegated_sub": "external-user", "documents": map[string]string{"example.entitlements/v1": "not-a-digest"},
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if _, err := verifier.Verify(malformed); !errors.Is(err, documents.ErrInvalidReference) {
		t.Fatalf("malformed verification = %v", err)
	}

	digest := documents.Digest([]byte("x"))
	duplicatePayload := []byte(fmt.Sprintf(
		`{"iss":%q,"aud":["resource-b"],"iat":%d,"exp":%d,"delegated_sub":"external-user","documents":{"example.entitlements/v1":%q,"example.entitlements/v1":%q}}`,
		issuer, now.Unix(), now.Add(time.Minute).Unix(), digest, digest,
	))
	duplicate, err := signer.SignPayload(context.Background(), duplicatePayload, map[string]any{"typ": DelegatedAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(duplicate); !errors.Is(err, documents.ErrDuplicateReference) {
		t.Fatalf("duplicate verification = %v", err)
	}

	tooMany := map[string]string{}
	for i := 0; i <= documents.MaxReferences; i++ {
		tooMany[fmt.Sprintf("example.type%d/v1", i)] = digest
	}
	oversized, _ := signer.SignWithHeaders(context.Background(), jwt.MapClaims{
		"iss": issuer, "aud": []string{"resource-b"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		"delegated_sub": "external-user", "documents": tooMany,
	}, map[string]any{"typ": DelegatedAccessTokenType})
	if _, err := verifier.Verify(oversized); !errors.Is(err, documents.ErrTooManyReferences) {
		t.Fatalf("oversized verification = %v", err)
	}

	// No compatibility alias: the old escape-hatch key remains opaque and does
	// not populate the canonical top-level documents map.
	oldAttribute := base
	oldAttribute.Attributes = map[string]any{"policy_digest": strings.Repeat("a", 64)}
	token, err := authcore.MintDelegatedAccessToken(context.Background(), signer, oldAttribute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token)
	if err != nil || claims.Documents != nil {
		t.Fatalf("policy_digest compatibility alias appeared: %v, %v", claims.Documents, err)
	}
}

func TestRemoteApplicationDocumentsClaimsRejectedBeforeEarlyReturn(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "remote-kid")
	issuer := "https://site-a.example"
	now := time.Now()
	verifier := newDelegatedVerifier(t, signer, issuer, []string{"resource-b"})
	digest := documents.Digest([]byte("document"))
	claims := func(value any) jwt.MapClaims {
		return jwt.MapClaims{
			"iss": issuer, "aud": []string{"resource-b"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			"documents": value,
		}
	}
	sign := func(value any) string {
		t.Helper()
		token, err := signer.SignWithHeaders(context.Background(), claims(value), map[string]any{"typ": RemoteApplicationAccessTokenType})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	duplicatePayload := []byte(fmt.Sprintf(
		`{"iss":%q,"aud":["resource-b"],"iat":%d,"exp":%d,"documents":{"example.entitlements/v1":%q,"example.entitlements/v1":%q}}`,
		issuer, now.Unix(), now.Add(time.Minute).Unix(), digest, digest,
	))
	duplicate, err := signer.SignPayload(context.Background(), duplicatePayload, map[string]any{"typ": RemoteApplicationAccessTokenType})
	if err != nil {
		t.Fatal(err)
	}
	oversized := map[string]string{}
	for i := 0; i < documents.MaxReferences; i++ {
		oversized[fmt.Sprintf("example.%02d.%s/v1", i, strings.Repeat("x", 220))] = digest
	}

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{name: "present", token: sign(map[string]string{"example.entitlements/v1": digest}), want: documents.ErrWrongTokenType},
		{name: "malformed", token: sign(map[string]string{"example.entitlements/v1": "not-a-digest"}), want: documents.ErrInvalidReference},
		{name: "duplicate", token: duplicate, want: documents.ErrDuplicateReference},
		{name: "oversized", token: sign(oversized), want: documents.ErrReferencesTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := verifier.Verify(tt.token); !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDelegatedRawTokensRejectReservedDocumentsAttribute(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "federated-kid")
	issuer := "https://site-a.example"
	now := time.Now()
	verifier := newDelegatedVerifier(t, signer, issuer, []string{"resource-b"})
	digest := documents.Digest([]byte("document"))

	for _, withTopLevel := range []bool{false, true} {
		name := "nested only"
		claims := jwt.MapClaims{
			"iss": issuer, "aud": []string{"resource-b"}, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			"delegated_sub": "external-user",
			"attributes":    map[string]any{"documents": map[string]string{"example.entitlements/v1": digest}},
		}
		if withTopLevel {
			name = "nested and top-level"
			claims["documents"] = map[string]string{"example.entitlements/v1": digest}
		}
		t.Run(name, func(t *testing.T) {
			token, err := signer.SignWithHeaders(context.Background(), claims, map[string]any{"typ": DelegatedAccessTokenType})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := verifier.Verify(token); !errors.Is(err, documents.ErrReservedAttribute) {
				t.Fatalf("Verify() error = %v, want %v", err, documents.ErrReservedAttribute)
			}
		})
	}
}
