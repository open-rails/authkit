package authcore

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"testing"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

type rotatingDocumentKeySource struct {
	active jwtkit.Signer
	pubs   map[string]crypto.PublicKey
}

func (s *rotatingDocumentKeySource) ActiveSigner() jwtkit.Signer { return s.active }
func (s *rotatingDocumentKeySource) PublicKeys() map[string]crypto.PublicKey {
	return s.pubs
}

func TestServiceSignDocumentUsesConfiguredIssuerAndLiveKey(t *testing.T) {
	oldSigner, _ := jwtkit.NewRSASigner(2048, "kid-old")
	newSigner, _ := jwtkit.NewRSASigner(2048, "kid-new")
	source := &rotatingDocumentKeySource{
		active: oldSigner,
		pubs:   map[string]crypto.PublicKey{oldSigner.KID(): oldSigner.PublicKey()},
	}
	const issuer = "https://site-a.example"
	service, err := NewFromConfig(Config{Token: TokenConfig{
		Issuer: issuer, IssuedAudiences: []string{"site-b"}, ExpectedAudiences: []string{"site-b"},
	}, Keys: KeysConfig{Source: source}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope := documents.Envelope{
		Audiences: []string{"site-b"}, Type: "example.entitlements/v1", Payload: json.RawMessage(`{"limit":7}`),
	}
	oldDocument, err := service.SignDocument(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := documents.DecodeCompact(oldDocument.CompactJWS)
	if header.KeyID != "kid-old" {
		t.Fatalf("old kid = %q", header.KeyID)
	}
	decoded, err := documents.DecodeEnvelope(oldDocument.SignedPayload)
	if err != nil || decoded.Issuer != issuer {
		t.Fatalf("configured issuer = %q, err %v", decoded.Issuer, err)
	}

	source.active = newSigner
	source.pubs = map[string]crypto.PublicKey{
		oldSigner.KID(): oldSigner.PublicKey(), newSigner.KID(): newSigner.PublicKey(),
	}
	newDocument, err := service.SignDocument(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ = documents.DecodeCompact(newDocument.CompactJWS)
	if header.KeyID != "kid-new" {
		t.Fatalf("rotated kid = %q", header.KeyID)
	}

	v := verify.NewVerifier()
	if err := v.AddIssuer(issuer, nil, verify.IssuerOptions{RawKeys: source.pubs}); err != nil {
		t.Fatal(err)
	}
	for _, document := range []documents.SignedDocument{oldDocument, newDocument} {
		if _, err := v.VerifyDocument(context.Background(), document, documents.VerifyOptions{
			Issuer: issuer, Audience: "site-b", Type: document.Reference.Type, Reference: document.Reference,
		}); err != nil {
			t.Fatalf("verify %s: %v", document.Reference.Digest, err)
		}
	}

	envelope.Issuer = "https://other.example"
	if _, err := service.SignDocument(context.Background(), envelope); !errors.Is(err, documents.ErrIssuerMismatch) {
		t.Fatalf("issuer override = %v", err)
	}
	verifyOnly := NewService(Config{Token: TokenConfig{Issuer: issuer}}, Keyset{})
	if _, err := verifyOnly.SignDocument(context.Background(), documents.Envelope{}); !errors.Is(err, ErrMissingSigner) {
		t.Fatalf("missing signer = %v", err)
	}
}
