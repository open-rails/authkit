package documents

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDigestCollision is returned when a save would change the immutable
// payload or type stored under an existing digest.
var ErrDigestCollision = errors.New("document_digest_collision")

// Signer signs one envelope with the process's active AuthKit key and exposes
// the CURRENT public keys for self-verification. *embedded.Client satisfies it.
type Signer interface {
	SignDocument(ctx context.Context, envelope Envelope) (SignedDocument, error)
	PublicKeysByKID() map[string]crypto.PublicKey
}

// Store persists immutable signed documents by digest. Save may replace ONLY
// compact_jws for an existing digest (a re-signature of the same payload on
// key rotation); any payload or type change under an existing digest must fail
// with ErrDigestCollision. Lookup returns ErrNotFound for unknown digests.
type Store interface {
	SaveDocument(ctx context.Context, document SignedDocument) error
	Lookup(ctx context.Context, digest string) (SignedDocument, error)
}

// ServiceConfig declares one published document (ak#260). The host supplies
// its compiled payload; AuthKit owns the store, lifecycle, and invariants.
type ServiceConfig struct {
	// Type is the versioned application document type (e.g. "example.catalog/v1").
	Type string
	// Payload is the host-compiled application payload. Opaque to AuthKit.
	Payload json.RawMessage
	// Issuer is the signing AuthKit issuer (normally Config.Token.Issuer).
	Issuer string
	// Audiences are the signed envelope audiences readers verify against.
	Audiences []string
	// Signer signs and self-verifies (normally the *embedded.Client).
	Signer Signer
	// Postgres + Schema select AuthKit's own signed_documents table (Schema ""
	// means the default "profiles"). Ignored when Store is set.
	Postgres *pgxpool.Pool
	Schema   string
	// Store overrides the built-in Postgres store (tests / custom backends).
	Store Store
}

// Service owns the publish lifecycle of ONE immutable signed document:
// sign -> verify -> persist -> re-read -> re-verify at construction, a
// digest-stable re-signature when the signing key rotates (EnsureSigningKID /
// CurrentDigest repair), and content-addressed lookups for the publication
// route. Construct with NewService; the zero value is unusable.
type Service struct {
	documentType string
	issuer       string
	audiences    []string
	signer       Signer
	store        Store

	reference     Reference
	payload       json.RawMessage
	signedPayload []byte

	rotationMu sync.Mutex
}

// NewService validates the config and runs the full publish lifecycle: the
// document is signed, self-verified, persisted, re-read, and re-verified
// before the Service (and therefore its digest) becomes observable.
func NewService(ctx context.Context, cfg ServiceConfig) (*Service, error) {
	if cfg.Signer == nil {
		return nil, errors.New("authkit/documents: ServiceConfig.Signer is required")
	}
	documentType, err := NormalizeType(cfg.Type)
	if err != nil {
		return nil, fmt.Errorf("authkit/documents: invalid ServiceConfig.Type %q: %w", cfg.Type, err)
	}
	if len(cfg.Payload) == 0 || !json.Valid(cfg.Payload) {
		return nil, errors.New("authkit/documents: ServiceConfig.Payload must be valid JSON")
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return nil, errors.New("authkit/documents: ServiceConfig.Issuer is required")
	}
	audiences := normalizeDedup(cfg.Audiences)
	if len(audiences) == 0 {
		return nil, errors.New("authkit/documents: ServiceConfig.Audiences is required")
	}
	store := cfg.Store
	if store == nil {
		if cfg.Postgres == nil {
			return nil, errors.New("authkit/documents: ServiceConfig requires Postgres (or an explicit Store)")
		}
		if store, err = newPostgresStore(cfg.Postgres, cfg.Schema); err != nil {
			return nil, err
		}
	}

	s := &Service{
		documentType: documentType,
		issuer:       issuer,
		audiences:    audiences,
		signer:       cfg.Signer,
		store:        store,
		payload:      append(json.RawMessage(nil), cfg.Payload...),
	}
	document, err := s.sign(ctx)
	if err != nil {
		return nil, err
	}
	s.reference = document.Reference
	s.signedPayload = append([]byte(nil), document.SignedPayload...)
	if err := s.persist(ctx, document); err != nil {
		return nil, err
	}
	if _, _, err := s.readValidated(ctx); err != nil {
		return nil, fmt.Errorf("authkit/documents: activate published document: %w", err)
	}
	return s, nil
}

// Reference returns the process snapshot reference of the published document.
func (s *Service) Reference() Reference { return s.reference }

// Payload returns a copy of the host payload this Service published.
func (s *Service) Payload() json.RawMessage {
	return append(json.RawMessage(nil), s.payload...)
}

// Lookup returns any persisted document by digest (the publication route's
// lookup seam) — historical digests included, not just the process snapshot.
func (s *Service) Lookup(ctx context.Context, digest string) (SignedDocument, error) {
	if s == nil || s.store == nil {
		return SignedDocument{}, errors.New("authkit/documents: service is unavailable")
	}
	return s.store.Lookup(ctx, digest)
}

// CurrentDigest re-validates the persisted artifact behind the process
// snapshot and returns its digest. An artifact that fails signature
// verification (e.g. it was re-signed by a key this process no longer serves)
// is repaired in place by a fresh digest-stable re-signature.
func (s *Service) CurrentDigest(ctx context.Context) (string, error) {
	if s == nil || s.store == nil || s.signer == nil {
		return "", errors.New("authkit/documents: service is unavailable")
	}
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	stored, err := s.store.Lookup(ctx, s.reference.Digest)
	if err != nil {
		return "", fmt.Errorf("read published document artifact: %w", err)
	}
	if err := s.validateStoredPayload(stored); err != nil {
		return "", fmt.Errorf("validate published document payload: %w", err)
	}
	if err := s.validateStoredDocument(stored); err != nil {
		if _, repairErr := s.renewStoredDocument(ctx, stored, ""); repairErr != nil {
			return "", fmt.Errorf("repair invalid published document artifact after %v: %w", err, repairErr)
		}
	}
	return s.reference.Digest, nil
}

// EnsureSigningKID reconciles the persisted artifact's signature with the key
// that just signed a token stamping this document's digest (ak#261): when the
// stored compact JWS is not signed by tokenKID, the document is re-signed —
// digest-stable — so a verifier holding the token's JWKS can always verify the
// document it references.
func (s *Service) EnsureSigningKID(ctx context.Context, tokenKID string) error {
	if s == nil || s.store == nil || s.signer == nil {
		return errors.New("authkit/documents: service is unavailable")
	}
	tokenKID = strings.TrimSpace(tokenKID)
	if tokenKID == "" {
		return errors.New("authkit/documents: token signing key id is unavailable")
	}

	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	stored, err := s.store.Lookup(ctx, s.reference.Digest)
	if err != nil {
		return fmt.Errorf("read published document artifact: %w", err)
	}
	if err := s.validateStoredPayload(stored); err != nil {
		return fmt.Errorf("validate published document payload: %w", err)
	}
	header, compactPayload, decodeErr := DecodeCompact(stored.CompactJWS)
	storedKID := ""
	if decodeErr == nil && bytes.Equal(compactPayload, stored.SignedPayload) {
		storedKID = strings.TrimSpace(header.KeyID)
	}
	if storedKID == tokenKID {
		if err := s.validateStoredDocument(stored); err == nil {
			return nil
		}
	}
	_, err = s.renewStoredDocument(ctx, stored, tokenKID)
	return err
}

// sign signs the configured envelope and self-verifies the result before it
// can be persisted or referenced.
func (s *Service) sign(ctx context.Context) (SignedDocument, error) {
	document, err := s.signer.SignDocument(ctx, Envelope{
		Issuer:    s.issuer,
		Audiences: append([]string(nil), s.audiences...),
		Type:      s.documentType,
		Payload:   s.payload,
	})
	if err != nil {
		return SignedDocument{}, fmt.Errorf("sign document: %w", err)
	}
	if document.Reference.Type != s.documentType || document.Reference.Validate() != nil {
		return SignedDocument{}, errors.New("sign document: invalid reference")
	}
	if err := s.verifyDocument(document, document.Reference, document.SignedPayload); err != nil {
		return SignedDocument{}, fmt.Errorf("validate signed document: %w", err)
	}
	return document, nil
}

// persist saves the immutable artifact, then re-reads and re-verifies it: the
// durable row is proven serveable before anything can reference its digest.
func (s *Service) persist(ctx context.Context, document SignedDocument) error {
	if err := s.store.SaveDocument(ctx, document); err != nil {
		return fmt.Errorf("persist document: %w", err)
	}
	stored, err := s.store.Lookup(ctx, document.Reference.Digest)
	if err != nil {
		return fmt.Errorf("read persisted document: %w", err)
	}
	if stored.Reference != document.Reference || !bytes.Equal(stored.SignedPayload, document.SignedPayload) {
		return errors.New("persisted document does not match the signed document")
	}
	if err := s.verifyDocument(stored, document.Reference, document.SignedPayload); err != nil {
		return fmt.Errorf("validate persisted document: %w", err)
	}
	return nil
}

// renewStoredDocument re-signs the process payload and persists the result.
// The renewal must be digest-stable: any drift from the process snapshot —
// reference, payload bytes, or a concurrent replacement by another key —
// fails loudly instead of activating a different document.
func (s *Service) renewStoredDocument(ctx context.Context, stored SignedDocument, expectedKID string) (string, error) {
	renewed, err := s.sign(ctx)
	if err != nil {
		return "", err
	}
	renewedHeader, _, err := DecodeCompact(renewed.CompactJWS)
	if err != nil {
		return "", fmt.Errorf("inspect renewed document signature: %w", err)
	}
	expectedKID = strings.TrimSpace(expectedKID)
	if expectedKID != "" && renewedHeader.KeyID != expectedKID {
		return "", fmt.Errorf("active signing key changed while renewing document: expected=%q document=%q", expectedKID, renewedHeader.KeyID)
	}
	if renewed.Reference != s.reference || !bytes.Equal(renewed.SignedPayload, stored.SignedPayload) ||
		!bytes.Equal(renewed.SignedPayload, s.signedPayload) {
		return "", errors.New("renewed document changed the process snapshot")
	}
	if err := s.persist(ctx, renewed); err != nil {
		return "", err
	}
	_, persistedKID, err := s.readValidated(ctx)
	if err != nil {
		return "", fmt.Errorf("read renewed document artifact: %w", err)
	}
	if persistedKID != renewedHeader.KeyID {
		return "", fmt.Errorf("renewed document was concurrently replaced by key %q", persistedKID)
	}
	return persistedKID, nil
}

// readValidated re-reads the snapshot artifact, fully verifies it, and returns
// it with its signing key id.
func (s *Service) readValidated(ctx context.Context) (SignedDocument, string, error) {
	document, err := s.store.Lookup(ctx, s.reference.Digest)
	if err != nil {
		return SignedDocument{}, "", fmt.Errorf("read published document artifact: %w", err)
	}
	if err := s.verifyDocument(document, s.reference, s.signedPayload); err != nil {
		return SignedDocument{}, "", err
	}
	header, _, err := DecodeCompact(document.CompactJWS)
	if err != nil {
		return SignedDocument{}, "", err
	}
	if strings.TrimSpace(header.KeyID) == "" {
		return SignedDocument{}, "", errors.New("document signing key id is unavailable")
	}
	return document, header.KeyID, nil
}

// validateStoredPayload checks the cheap byte invariants against the process
// snapshot without signature verification.
func (s *Service) validateStoredPayload(document SignedDocument) error {
	if document.Reference != s.reference || s.reference.Type != s.documentType || s.reference.Validate() != nil {
		return ErrInvalidReference
	}
	if len(s.signedPayload) == 0 {
		return errors.New("process document payload is unavailable")
	}
	if Digest(document.SignedPayload) != s.reference.Digest {
		return ErrDigestMismatch
	}
	if !bytes.Equal(document.SignedPayload, s.signedPayload) {
		return errors.New("document payload does not match the process snapshot")
	}
	return nil
}

// validateStoredDocument is the full check: byte invariants plus signature
// verification against the signer's CURRENT public keys and envelope
// issuer/audiences equality.
func (s *Service) validateStoredDocument(document SignedDocument) error {
	if err := s.validateStoredPayload(document); err != nil {
		return err
	}
	return s.verifyDocument(document, s.reference, s.signedPayload)
}

// verifyDocument self-verifies a document against the signer's current public
// keys and this Service's expected issuer/audiences/type/reference. It is the
// producer-side counterpart of verify.Verifier.VerifyDocument, without a
// cross-site trust registry: the only trusted keys are the process's own.
func (s *Service) verifyDocument(document SignedDocument, reference Reference, expectedSignedPayload []byte) error {
	if document.Reference != reference || reference.Type != s.documentType || reference.Validate() != nil {
		return ErrInvalidReference
	}
	header, payload, err := DecodeCompact(document.CompactJWS)
	if err != nil {
		return err
	}
	if header.Type != JOSEType {
		return ErrWrongJOSEType
	}
	if !supportedSigningAlgorithm(header.Algorithm) {
		return ErrUnsupportedAlgorithm
	}
	if header.KeyID == "" {
		return ErrUnknownKey
	}
	if !bytes.Equal(payload, document.SignedPayload) || Digest(payload) != reference.Digest {
		return ErrDigestMismatch
	}
	if expectedSignedPayload != nil && !bytes.Equal(payload, expectedSignedPayload) {
		return errors.New("document payload does not match the signed process snapshot")
	}

	key := s.signer.PublicKeysByKID()[header.KeyID]
	if key == nil {
		return ErrUnknownKey
	}
	parts := strings.Split(document.CompactJWS, ".")
	if len(parts) != 3 {
		return ErrMalformedJWS
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrMalformedJWS
	}
	method := jwt.GetSigningMethod(header.Algorithm)
	if method == nil {
		return ErrUnsupportedAlgorithm
	}
	if err := method.Verify(parts[0]+"."+parts[1], signature, key); err != nil {
		return ErrInvalidSignature
	}

	envelope, err := DecodeEnvelope(payload)
	if err != nil {
		return err
	}
	if envelope.Issuer != s.issuer {
		return ErrIssuerMismatch
	}
	if envelope.Type != s.documentType {
		return ErrTypeMismatch
	}
	if !equalStrings(envelope.Audiences, s.audiences) {
		return ErrAudienceMismatch
	}
	return nil
}

func normalizeDedup(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
