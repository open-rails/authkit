package verify

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
)

const testDocumentType = "example.entitlements/v1"

func testSignedDocument(t *testing.T, signer jwtkit.Signer, issuer string) documents.SignedDocument {
	t.Helper()
	document, err := documents.Sign(context.Background(), signer, documents.Envelope{
		Issuer: issuer, Audiences: []string{"resource-b"}, Type: testDocumentType,
		Payload: json.RawMessage(`{"limit":7}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func testDocumentVerifier(t *testing.T, issuer string, signer *jwtkit.RSASigner) *Verifier {
	t.Helper()
	v := NewVerifier()
	if err := v.AddIssuer(issuer, nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}); err != nil {
		t.Fatal(err)
	}
	return v
}

func verifyOptions(issuer string, document documents.SignedDocument) documents.VerifyOptions {
	return documents.VerifyOptions{
		Issuer: issuer, Audience: "resource-b", Type: document.Reference.Type, Reference: document.Reference,
	}
}

func TestVerifyDocumentRoundTripAndMetadataMismatches(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-a")
	issuer := "https://site-a.example"
	document := testSignedDocument(t, signer, issuer)
	v := testDocumentVerifier(t, issuer, signer)
	if err := v.AddIssuer("https://other.example", nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}); err != nil {
		t.Fatal(err)
	}

	envelope, err := v.VerifyDocument(context.Background(), document, verifyOptions(issuer, document))
	if err != nil {
		t.Fatal(err)
	}
	if string(envelope.Payload) != `{"limit":7}` {
		t.Fatalf("payload = %s", envelope.Payload)
	}
	if _, err := v.Verify(document.CompactJWS); err == nil {
		t.Fatal("a signed document must not verify as an access token")
	}

	badDigest := document.Reference
	badDigest.Digest = "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name string
		opts documents.VerifyOptions
		want error
	}{
		{name: "issuer", opts: documents.VerifyOptions{Issuer: "https://other.example", Audience: "resource-b", Type: testDocumentType, Reference: document.Reference}, want: documents.ErrIssuerMismatch},
		{name: "audience", opts: documents.VerifyOptions{Issuer: issuer, Audience: "resource-c", Type: testDocumentType, Reference: document.Reference}, want: documents.ErrAudienceMismatch},
		{name: "type", opts: documents.VerifyOptions{Issuer: issuer, Audience: "resource-b", Type: "example.other/v1", Reference: document.Reference}, want: documents.ErrTypeMismatch},
		{name: "reference", opts: documents.VerifyOptions{Issuer: issuer, Audience: "resource-b", Type: testDocumentType, Reference: badDigest}, want: documents.ErrDigestMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := v.VerifyDocument(context.Background(), document, tt.opts); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyDocumentRejectsTamperingAndWrongJOSEProfile(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-a")
	issuer := "https://site-a.example"
	document := testSignedDocument(t, signer, issuer)
	v := testDocumentVerifier(t, issuer, signer)
	opts := verifyOptions(issuer, document)

	t.Run("retained payload mismatch", func(t *testing.T) {
		bad := document
		bad.SignedPayload = append(append([]byte(nil), bad.SignedPayload...), ' ')
		if _, err := v.VerifyDocument(context.Background(), bad, opts); !errors.Is(err, documents.ErrDigestMismatch) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("signature", func(t *testing.T) {
		bad := document
		parts := strings.Split(bad.CompactJWS, ".")
		signature := []byte(parts[2])
		if signature[0] == 'A' {
			signature[0] = 'B'
		} else {
			signature[0] = 'A'
		}
		parts[2] = string(signature)
		bad.CompactJWS = strings.Join(parts, ".")
		if _, err := v.VerifyDocument(context.Background(), bad, opts); !errors.Is(err, documents.ErrInvalidSignature) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("malformed compact", func(t *testing.T) {
		bad := document
		bad.CompactJWS = "not.a.jws"
		if _, err := v.VerifyDocument(context.Background(), bad, opts); !errors.Is(err, documents.ErrMalformedJWS) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong typ", func(t *testing.T) {
		compact, err := signer.SignPayload(context.Background(), document.SignedPayload, map[string]any{"typ": "JWT"})
		if err != nil {
			t.Fatal(err)
		}
		bad := document
		bad.CompactJWS = compact
		if _, err := v.VerifyDocument(context.Background(), bad, opts); !errors.Is(err, documents.ErrWrongJOSEType) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		other, _ := jwtkit.NewRSASigner(2048, "kid-b")
		otherVerifier := testDocumentVerifier(t, issuer, other)
		if _, err := otherVerifier.VerifyDocument(context.Background(), document, opts); !errors.Is(err, documents.ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("duplicate envelope field", func(t *testing.T) {
		raw := []byte(`{"iss":"` + issuer + `","aud":["resource-b"],"type":"` + testDocumentType + `","type":"` + testDocumentType + `","payload":{}}`)
		compact, err := signer.SignPayload(context.Background(), raw, map[string]any{"typ": documents.JOSEType})
		if err != nil {
			t.Fatal(err)
		}
		reference, _ := documents.ReferenceFor(testDocumentType, raw)
		bad := documents.SignedDocument{CompactJWS: compact, Reference: reference, SignedPayload: raw}
		if _, err := v.VerifyDocument(context.Background(), bad, verifyOptions(issuer, bad)); !errors.Is(err, documents.ErrInvalidEnvelope) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		ed, _ := jwtkit.NewEd25519Signer("ed-kid")
		edDocument := testSignedDocument(t, ed, issuer)
		rsaOnly := NewVerifier(WithAlgorithms("RS256"))
		if err := rsaOnly.AddIssuer(issuer, nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{ed.KID(): ed.PublicKey()}}); err != nil {
			t.Fatal(err)
		}
		if _, err := rsaOnly.VerifyDocument(context.Background(), edDocument, verifyOptions(issuer, edDocument)); !errors.Is(err, documents.ErrUnsupportedAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestVerifyDocumentNeverSelectsKeysFromUnverifiedPayloadIssuer(t *testing.T) {
	const sharedKID = "shared-kid"
	trustedSigner, _ := jwtkit.NewRSASigner(2048, sharedKID)
	attackerSigner, _ := jwtkit.NewRSASigner(2048, sharedKID)
	trustedIssuer := "https://trusted.example"
	attackerIssuer := "https://attacker.example"
	document := testSignedDocument(t, attackerSigner, attackerIssuer)

	v := NewVerifier()
	if err := v.AddIssuer(trustedIssuer, nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{sharedKID: trustedSigner.PublicKey()}}); err != nil {
		t.Fatal(err)
	}
	if err := v.AddIssuer(attackerIssuer, nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{sharedKID: attackerSigner.PublicKey()}}); err != nil {
		t.Fatal(err)
	}

	// The payload claims attackerIssuer, but that JSON is not authenticated yet.
	// Key lookup must use trustedIssuer and fail the signature before metadata is
	// decoded; selecting the payload issuer's key would instead authenticate it.
	if _, err := v.VerifyDocument(context.Background(), document, verifyOptions(trustedIssuer, document)); !errors.Is(err, documents.ErrInvalidSignature) {
		t.Fatalf("VerifyDocument() error = %v, want %v", err, documents.ErrInvalidSignature)
	}
}

func TestVerifyDocumentIndependentIssuersAndJWKSRotation(t *testing.T) {
	t.Run("independent issuers and types", func(t *testing.T) {
		a, _ := jwtkit.NewRSASigner(2048, "kid-a")
		b, _ := jwtkit.NewEd25519Signer("kid-b")
		docA := testSignedDocument(t, a, "https://a.example")
		docB, err := documents.Sign(context.Background(), b, documents.Envelope{
			Issuer: "https://b.example", Audiences: []string{"resource-b"}, Type: "example.catalog/v2", Payload: json.RawMessage(`{"enabled":true}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		v := NewVerifier()
		_ = v.AddIssuer("https://a.example", nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{a.KID(): a.PublicKey()}})
		_ = v.AddIssuer("https://b.example", nil, IssuerOptions{RawKeys: map[string]crypto.PublicKey{b.KID(): b.PublicKey()}})
		for issuer, document := range map[string]documents.SignedDocument{"https://a.example": docA, "https://b.example": docB} {
			if _, err := v.VerifyDocument(context.Background(), document, verifyOptions(issuer, document)); err != nil {
				t.Fatalf("%s: %v", issuer, err)
			}
		}
	})

	t.Run("unknown kid refresh", func(t *testing.T) {
		oldSigner, _ := jwtkit.NewRSASigner(2048, "kid-old")
		newSigner, _ := jwtkit.NewRSASigner(2048, "kid-new")
		var (
			mu      sync.RWMutex
			current = jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(oldSigner.PublicKey(), oldSigner.KID(), oldSigner.Algorithm())}}
			hits    atomic.Int32
		)
		jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			mu.RLock()
			defer mu.RUnlock()
			_ = json.NewEncoder(w).Encode(current)
		}))
		defer jwksServer.Close()

		issuer := jwksServer.URL
		v := NewVerifier()
		if err := v.AddIssuer(issuer, nil, IssuerOptions{JWKSURI: jwksServer.URL}); err != nil {
			t.Fatal(err)
		}
		oldDocument := testSignedDocument(t, oldSigner, issuer)
		if _, err := v.VerifyDocument(context.Background(), oldDocument, verifyOptions(issuer, oldDocument)); err != nil {
			t.Fatalf("old key: %v", err)
		}
		mu.Lock()
		current = jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(newSigner.PublicKey(), newSigner.KID(), newSigner.Algorithm())}}
		mu.Unlock()
		newDocument := testSignedDocument(t, newSigner, issuer)
		if _, err := v.VerifyDocument(context.Background(), newDocument, verifyOptions(issuer, newDocument)); err != nil {
			t.Fatalf("rotated key: %v", err)
		}
		if hits.Load() < 2 {
			t.Fatalf("JWKS hits = %d, want initial fetch + unknown-kid refresh", hits.Load())
		}
	})
}
