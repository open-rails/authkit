package documents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

type alteredHeaderSigner struct {
	base      *jwtkit.RSASigner
	kid       string
	algorithm string
	headers   map[string]any
}

func (s alteredHeaderSigner) Algorithm() string { return s.algorithm }
func (s alteredHeaderSigner) KID() string       { return s.kid }
func (s alteredHeaderSigner) Sign(ctx context.Context, claims jwt.MapClaims) (string, error) {
	return s.base.Sign(ctx, claims)
}
func (s alteredHeaderSigner) SignPayload(ctx context.Context, payload []byte, headers map[string]any) (string, error) {
	merged := make(map[string]any, len(headers)+len(s.headers))
	for key, value := range headers {
		merged[key] = value
	}
	for key, value := range s.headers {
		merged[key] = value
	}
	return s.base.SignPayload(ctx, payload, merged)
}

func TestSignRetainsExactEnvelopeBytes(t *testing.T) {
	signers := []jwtkit.Signer{}
	rsaSigner, err := jwtkit.NewRSASigner(2048, "rsa-kid")
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := jwtkit.NewEd25519Signer("ed-kid")
	if err != nil {
		t.Fatal(err)
	}
	signers = append(signers, rsaSigner, edSigner)

	for _, signer := range signers {
		t.Run(signer.Algorithm(), func(t *testing.T) {
			envelope := Envelope{
				Issuer:    " https://site-a.example ",
				Audiences: []string{"site-b", "site-b"},
				Type:      " example.catalog/v1 ",
				Payload:   json.RawMessage(`{ "limit": 7 }`),
			}
			document, err := Sign(context.Background(), signer, envelope)
			if err != nil {
				t.Fatal(err)
			}
			normalized, _ := NormalizeEnvelope(envelope)
			wantPayload, _ := json.Marshal(normalized)
			if !bytes.Equal(document.SignedPayload, wantPayload) {
				t.Fatalf("signed payload changed\n got: %s\nwant: %s", document.SignedPayload, wantPayload)
			}
			header, payload, err := DecodeCompact(document.CompactJWS)
			if err != nil {
				t.Fatal(err)
			}
			if header.Type != JOSEType || header.KeyID != signer.KID() || header.Algorithm != signer.Algorithm() {
				t.Fatalf("header = %+v", header)
			}
			if !bytes.Equal(payload, document.SignedPayload) || document.Reference.Digest != Digest(payload) {
				t.Fatal("compact payload/reference do not identify the retained exact bytes")
			}
			decoded, err := DecodeEnvelope(payload)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Issuer != "https://site-a.example" || decoded.Type != "example.catalog/v1" || len(decoded.Audiences) != 1 {
				t.Fatalf("decoded envelope = %+v", decoded)
			}
		})
	}
}

func TestStrictEnvelopeAndReferenceValidation(t *testing.T) {
	duplicate := []byte(`{"iss":"https://a.example","iss":"https://b.example","aud":["b"],"type":"example.catalog/v1","payload":{}}`)
	if _, err := DecodeEnvelope(duplicate); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("duplicate envelope field: %v", err)
	}

	oversized := Envelope{
		Issuer: "https://a.example", Audiences: []string{"b"}, Type: "example.catalog/v1",
		Payload: json.RawMessage(`"` + strings.Repeat("x", MaxPayloadBytes) + `"`),
	}
	signer, _ := jwtkit.NewRSASigner(2048, "kid")
	if _, err := Sign(context.Background(), signer, oversized); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized payload: %v", err)
	}

	digest := Digest([]byte("payload"))
	references, err := NormalizeReferences(map[string]string{
		" example.catalog/v1 ": strings.ToUpper(digest),
		"example.other/v2":     digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if references["example.catalog/v1"] != digest || len(references) != 2 {
		t.Fatalf("normalized references = %v", references)
	}
	if _, err := NormalizeReferences(map[string]string{
		"example.catalog/v1":  digest,
		" example.catalog/v1": digest,
	}); !errors.Is(err, ErrDuplicateReference) {
		t.Fatalf("normalization collision: %v", err)
	}
	raw := []byte(`{"example.catalog/v1":"` + digest + `","example.catalog/v1":"` + digest + `"}`)
	if _, err := ParseReferencesJSON(raw); !errors.Is(err, ErrDuplicateReference) {
		t.Fatalf("duplicate reference: %v", err)
	}
	if err := ValidateType("example.catalog"); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("unversioned type: %v", err)
	}
}

func TestSignRejectsInvalidProtectedHeaders(t *testing.T) {
	base, err := jwtkit.NewRSASigner(2048, "actual-kid")
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		Issuer: "https://site-a.example", Audiences: []string{"site-b"},
		Type: "example.catalog/v1", Payload: json.RawMessage(`{}`),
	}
	tests := []struct {
		name   string
		signer jwtkit.Signer
		want   error
	}{
		{name: "empty kid", signer: alteredHeaderSigner{base: base, algorithm: "RS256"}, want: ErrUnknownKey},
		{name: "mismatched kid", signer: alteredHeaderSigner{base: base, kid: "reported-kid", algorithm: "RS256"}, want: ErrUnknownKey},
		{name: "wrong typ", signer: alteredHeaderSigner{base: base, kid: base.KID(), algorithm: "RS256", headers: map[string]any{"typ": "JWT"}}, want: ErrWrongJOSEType},
		{name: "mismatched alg", signer: alteredHeaderSigner{base: base, kid: base.KID(), algorithm: "EdDSA"}, want: ErrUnsupportedAlgorithm},
		{name: "unsupported alg", signer: alteredHeaderSigner{base: base, kid: base.KID(), algorithm: "HS256"}, want: ErrUnsupportedAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Sign(context.Background(), tt.signer, envelope); !errors.Is(err, tt.want) {
				t.Fatalf("Sign() error = %v, want %v", err, tt.want)
			}
		})
	}
}
