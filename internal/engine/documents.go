package engine

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// SignDocument signs through the engine's live key source, so normal AuthKit
// key rotation applies without exposing private key material to the host.
func (s *Engine) SignDocument(ctx context.Context, envelope documents.Envelope) (documents.SignedDocument, error) {
	signer := s.keys.ActiveSigner()
	if signer == nil {
		return documents.SignedDocument{}, iam.ErrSigningNotConfigured
	}
	issuer := strings.TrimSpace(s.cfg.Token.Issuer)
	if strings.TrimSpace(envelope.Issuer) == "" {
		envelope.Issuer = issuer
	} else if issuer != "" && strings.TrimSpace(envelope.Issuer) != issuer {
		return documents.SignedDocument{}, documents.ErrIssuerMismatch
	}
	return documents.Sign(ctx, signer, envelope)
}

// publishedDocuments is the set of documents this engine publishes, one per type.
type publishedDocuments struct {
	mu        sync.RWMutex
	providers []documents.Provider
}

// PublishDocument signs p with this deployment's key, stores it, and from then
// on serves it to Config.Documents.Readers and stamps its reference into every
// delegated token this deployment mints. Each type is published once.
func (s *Engine) PublishDocument(ctx context.Context, p documents.Publication) (documents.Reference, error) {
	if err := s.requirePG(); err != nil {
		return documents.Reference{}, err
	}
	if len(s.cfg.Documents.Readers) == 0 {
		return documents.Reference{}, errors.New("authkit: PublishDocument needs Config.Documents.Readers; a document nobody may read is never published")
	}
	typ, err := documents.NormalizeType(p.Type)
	if err != nil {
		return documents.Reference{}, err
	}
	s.published.mu.Lock()
	defer s.published.mu.Unlock()
	for _, existing := range s.published.providers {
		if existing.Reference().Type == typ {
			return documents.Reference{}, errors.New("authkit: document type " + typ + " is already published")
		}
	}
	svc, err := documents.NewService(ctx, documents.ServiceConfig{
		Type:      typ,
		Payload:   p.Payload,
		Issuer:    s.cfg.Token.Issuer,
		Audiences: p.Audiences,
		Signer:    s,
		Store:     s.documentStore(),
	})
	if err != nil {
		return documents.Reference{}, err
	}
	s.published.providers = append(s.published.providers, svc)
	return svc.Reference(), nil
}

func (s *Engine) publishedDocuments() []documents.Provider {
	s.published.mu.RLock()
	defer s.published.mu.RUnlock()
	return append([]documents.Provider(nil), s.published.providers...)
}

// LookupDocument returns any stored signed document by digest.
func (s *Engine) LookupDocument(ctx context.Context, digest string) (documents.SignedDocument, error) {
	if err := s.requirePG(); err != nil {
		return documents.SignedDocument{}, err
	}
	return s.documentStore().Lookup(ctx, digest)
}

var errDelegatedDocumentUnavailable = errmodel.E(errmodel.CodeDelegatedDocumentUnavailable)

// delegatedDocuments merges the caller's document references with every
// published document. A caller reference to a published type must carry its
// current digest.
func (s *Engine) delegatedDocuments(extra map[string]string) (map[string]string, []documents.Provider, error) {
	providers := s.publishedDocuments()
	refs := make(map[string]string, len(extra)+len(providers))
	for typ, digest := range extra {
		refs[typ] = digest
	}
	for _, p := range providers {
		ref := p.Reference()
		if existing, dup := refs[ref.Type]; dup && existing != ref.Digest {
			return nil, nil, errDelegatedDocumentUnavailable
		}
		refs[ref.Type] = ref.Digest
	}
	return refs, providers, nil
}

// reconcileDocumentKeys makes every stamped published document verifiable
// with the key that signed the token (re-signing it digest-stable after a key
// rotation) and proves each stored digest is still the stamped one.
func reconcileDocumentKeys(ctx context.Context, providers []documents.Provider, refs map[string]string, tokenKID string) error {
	for _, p := range providers {
		if err := p.EnsureSigningKID(ctx, tokenKID); err != nil {
			return errmodel.E(errmodel.CodeDelegatedDocumentUnavailable, errmodel.WithCause(err))
		}
		digest, err := p.CurrentDigest(ctx)
		if err != nil || digest != refs[p.Reference().Type] {
			return errmodel.E(errmodel.CodeDelegatedDocumentUnavailable, errmodel.WithCause(err))
		}
	}
	return nil
}
