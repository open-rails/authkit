package documents

// ak#260 Service lifecycle mechanics over a fake store: publish
// (sign->verify->persist->re-read->re-verify), digest-stable KID-rotation
// repair, and the fail-loud invariants when the stored artifact drifts from
// the process snapshot. The engine's Postgres store and the mounted route are
// covered end-to-end in authhttp.

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
)

// rotatableSigner implements Signer over swappable jwtkit signers, keeping
// every historical public key visible (the JWKS shape during rotation).
type rotatableSigner struct {
	mu     sync.Mutex
	active *jwtkit.RSASigner
	pubs   map[string]crypto.PublicKey
}

func newRotatableSigner(t *testing.T, kid string) *rotatableSigner {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, kid)
	if err != nil {
		t.Fatal(err)
	}
	return &rotatableSigner{
		active: signer,
		pubs:   map[string]crypto.PublicKey{kid: signer.PublicKey()},
	}
}

func (s *rotatableSigner) rotate(t *testing.T, kid string) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, kid)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = signer
	s.pubs[kid] = signer.PublicKey()
}

// dropKey removes a public key, simulating a hard rotation where the old key
// left the JWKS entirely.
func (s *rotatableSigner) dropKey(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pubs, kid)
}

func (s *rotatableSigner) SignDocument(ctx context.Context, envelope Envelope) (SignedDocument, error) {
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	return Sign(ctx, active, envelope)
}

func (s *rotatableSigner) PublicKeysByKID() map[string]crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]crypto.PublicKey, len(s.pubs))
	for kid, key := range s.pubs {
		out[kid] = key
	}
	return out
}

// fakeStore is an in-memory Store with the same immutability contract as the
// Postgres store, plus direct mutation seams for drift tests.
type fakeStore struct {
	mu   sync.Mutex
	rows map[string]SignedDocument
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]SignedDocument{}} }

func (s *fakeStore) SaveDocument(_ context.Context, document SignedDocument) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.rows[document.Reference.Digest]; ok {
		if existing.Reference.Type != document.Reference.Type ||
			string(existing.SignedPayload) != string(document.SignedPayload) {
			return ErrDigestCollision
		}
	}
	s.rows[document.Reference.Digest] = document
	return nil
}

func (s *fakeStore) Lookup(_ context.Context, digest string) (SignedDocument, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	document, ok := s.rows[digest]
	if !ok {
		return SignedDocument{}, ErrNotFound
	}
	return document, nil
}

func (s *fakeStore) tamper(digest string, mutate func(*SignedDocument)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	document := s.rows[digest]
	mutate(&document)
	s.rows[digest] = document
}

func serviceConfigForTest(signer Signer, store Store) ServiceConfig {
	return ServiceConfig{
		Type:      "example.catalog/v1",
		Payload:   json.RawMessage(`{"items":["a","b"]}`),
		Issuer:    "https://issuer.example",
		Audiences: []string{"reader.example", "reader.example", " "},
		Signer:    signer,
		Store:     store,
	}
}

func TestServicePublishLifecycle(t *testing.T) {
	ctx := context.Background()
	signer := newRotatableSigner(t, "key-1")
	store := newFakeStore()
	svc, err := NewService(ctx, serviceConfigForTest(signer, store))
	if err != nil {
		t.Fatal(err)
	}

	ref := svc.Reference()
	if ref.Type != "example.catalog/v1" || ref.Validate() != nil {
		t.Fatalf("reference = %+v", ref)
	}
	stored, err := svc.Lookup(ctx, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if Digest(stored.SignedPayload) != ref.Digest {
		t.Fatal("stored payload digest mismatch")
	}
	envelope, err := DecodeEnvelope(stored.SignedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Issuer != "https://issuer.example" || len(envelope.Audiences) != 1 {
		t.Fatalf("envelope = %+v (audiences must be trimmed + deduped)", envelope)
	}
	if string(envelope.Payload) != `{"items":["a","b"]}` {
		t.Fatalf("payload = %s", envelope.Payload)
	}

	digest, err := svc.CurrentDigest(ctx)
	if err != nil || digest != ref.Digest {
		t.Fatalf("CurrentDigest = %q, %v", digest, err)
	}
	if _, err := svc.Lookup(ctx, Digest([]byte("missing"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown digest = %v", err)
	}
}

func TestServiceConfigValidation(t *testing.T) {
	ctx := context.Background()
	signer := newRotatableSigner(t, "key-1")
	base := serviceConfigForTest(signer, newFakeStore())

	tests := []struct {
		name   string
		mutate func(*ServiceConfig)
	}{
		{"nil signer", func(c *ServiceConfig) { c.Signer = nil }},
		{"unversioned type", func(c *ServiceConfig) { c.Type = "example.catalog" }},
		{"invalid payload", func(c *ServiceConfig) { c.Payload = json.RawMessage(`{`) }},
		{"empty payload", func(c *ServiceConfig) { c.Payload = nil }},
		{"blank issuer", func(c *ServiceConfig) { c.Issuer = "  " }},
		{"no audiences", func(c *ServiceConfig) { c.Audiences = []string{" "} }},
		{"no store", func(c *ServiceConfig) { c.Store = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if _, err := NewService(ctx, cfg); err == nil {
				t.Fatal("want construction error")
			}
		})
	}
}

func TestServiceEnsureSigningKIDRepairsRotatedKey(t *testing.T) {
	ctx := context.Background()
	signer := newRotatableSigner(t, "key-1")
	store := newFakeStore()
	svc, err := NewService(ctx, serviceConfigForTest(signer, store))
	if err != nil {
		t.Fatal(err)
	}
	ref := svc.Reference()

	// Same-KID reconciliation is a no-op.
	if err := svc.EnsureSigningKID(ctx, "key-1"); err != nil {
		t.Fatal(err)
	}

	// Rotate; a token minted by key-2 must force a digest-stable re-signature.
	signer.rotate(t, "key-2")
	if err := svc.EnsureSigningKID(ctx, "key-2"); err != nil {
		t.Fatal(err)
	}
	stored, err := svc.Lookup(ctx, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := DecodeCompact(stored.CompactJWS)
	if err != nil {
		t.Fatal(err)
	}
	if header.KeyID != "key-2" {
		t.Fatalf("stored kid = %q after rotation repair", header.KeyID)
	}
	if stored.Reference != ref || Digest(payload) != ref.Digest {
		t.Fatal("repair changed the digest — renewal must be digest-stable")
	}

	// Stored artifact still signed by key-2 and key-2 still served: a key-2
	// token reconciles as a no-op even though the ACTIVE key moved on.
	signer.rotate(t, "key-3")
	if err := svc.EnsureSigningKID(ctx, "key-2"); err != nil {
		t.Fatal(err)
	}
	// But when key-2 is gone from the JWKS, a key-2 token cannot be repaired
	// by the key-3 signer — renewal refuses a KID it cannot produce.
	signer.dropKey("key-2")
	if err := svc.EnsureSigningKID(ctx, "key-2"); err == nil {
		t.Fatal("want error when the active signer no longer matches the token KID")
	}
	// And reconciling to the NEW active key succeeds.
	if err := svc.EnsureSigningKID(ctx, "key-3"); err != nil {
		t.Fatal(err)
	}
}

func TestServiceCurrentDigestRepairsUnverifiableArtifact(t *testing.T) {
	ctx := context.Background()
	signer := newRotatableSigner(t, "key-1")
	store := newFakeStore()
	svc, err := NewService(ctx, serviceConfigForTest(signer, store))
	if err != nil {
		t.Fatal(err)
	}
	ref := svc.Reference()

	// Hard rotation: key-1 vanished from the JWKS entirely; the stored
	// artifact no longer verifies and must be repaired in place.
	signer.rotate(t, "key-2")
	signer.dropKey("key-1")
	digest, err := svc.CurrentDigest(ctx)
	if err != nil || digest != ref.Digest {
		t.Fatalf("CurrentDigest = %q, %v", digest, err)
	}
	stored, err := svc.Lookup(ctx, ref.Digest)
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := DecodeCompact(stored.CompactJWS)
	if err != nil || header.KeyID != "key-2" {
		t.Fatalf("stored kid = %q, %v", header.KeyID, err)
	}
}

func TestServiceFailsLoudOnPayloadDrift(t *testing.T) {
	ctx := context.Background()
	signer := newRotatableSigner(t, "key-1")
	store := newFakeStore()
	svc, err := NewService(ctx, serviceConfigForTest(signer, store))
	if err != nil {
		t.Fatal(err)
	}
	ref := svc.Reference()

	// A store whose payload bytes drifted from the digest is NOT repairable —
	// the digest names different bytes, so repair would republish under a lie.
	store.tamper(ref.Digest, func(d *SignedDocument) {
		d.SignedPayload = []byte(`{"items":["evil"]}`)
	})
	if _, err := svc.CurrentDigest(ctx); err == nil {
		t.Fatal("want error on payload drift")
	}
	if err := svc.EnsureSigningKID(ctx, "key-1"); err == nil {
		t.Fatal("want error on payload drift")
	}
}

func TestNormalizeDedupAndEqualStrings(t *testing.T) {
	if got := normalizeDedup([]string{" a ", "a", "", "b"}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("normalizeDedup = %v", got)
	}
	if normalizeDedup([]string{" ", ""}) != nil {
		t.Fatal("all-blank must normalize to nil")
	}
	if !equalStrings([]string{"a"}, []string{"a"}) || equalStrings([]string{"a"}, []string{"b"}) || equalStrings([]string{"a"}, nil) {
		t.Fatal("equalStrings misbehaves")
	}
}
