package authhttp

// ak#260: the mounted published-document surface. AuthKit owns the store, the
// publish lifecycle (documents.Service), and this route; reader authorization
// is CONFIG (Config.Documents.ReaderSlugs) — never a host-written callback.

import (
	"context"
	"errors"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/verify"
)

// DocumentProvider is the published-document seam shared by the publication
// route (#260) and the delegated-token mint's document stamping (#261).
// *documents.Service implements it.
type DocumentProvider interface {
	// Reference is the process snapshot reference stamped into minted tokens.
	Reference() documents.Reference
	// Lookup serves any persisted digest for the publication route.
	Lookup(ctx context.Context, digest string) (documents.SignedDocument, error)
	// CurrentDigest re-validates (and repairs) the persisted snapshot artifact.
	CurrentDigest(ctx context.Context) (string, error)
	// EnsureSigningKID re-signs the artifact when it is not signed by the key
	// that just minted a token referencing it.
	EnsureSigningKID(ctx context.Context, tokenKID string) error
}

// WithDocuments wires published-document providers (normally *documents.Service
// values) into the HTTP layer: MountHandler serves their documents at
// GET|HEAD /.well-known/authkit/documents/{digest} (RouteDocuments), and the
// delegated-token mint route stamps and KID-reconciles their digests (#261).
// Requires Config.Documents.ReaderSlugs — NewServer refuses providers with no
// authorized readers (publication is never public) and reader slugs with no
// providers (dead config).
func WithDocuments(providers ...DocumentProvider) Option {
	return func(s *Service) { s.documentProviders = append(s.documentProviders, providers...) }
}

// documentsHandler builds the publication handler over every wired provider.
// Authorization: the request must verify as a remote application whose slug is
// in Config.Documents.ReaderSlugs. The verifier middleware authenticates; the
// publisher's authorize callback checks the resulting claims.
func (s *Service) documentsHandler() http.Handler {
	providers := s.documentProviders
	lookup := func(ctx context.Context, digest string) (documents.SignedDocument, error) {
		for _, p := range providers {
			document, err := p.Lookup(ctx, digest)
			if err == nil {
				return document, nil
			}
			if !errors.Is(err, documents.ErrNotFound) {
				return documents.SignedDocument{}, err
			}
		}
		return documents.SignedDocument{}, documents.ErrNotFound
	}
	readers := make(map[string]bool, len(s.svc.Config().Documents.ReaderSlugs))
	for _, slug := range s.svc.Config().Documents.ReaderSlugs {
		readers[slug] = true
	}
	authorize := func(r *http.Request) error {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok || claims.PrincipalKind() != authkit.PrincipalKindRemoteApplication ||
			!readers[claims.RemoteApplicationSlug] {
			return documents.ErrUnauthorized
		}
		return nil
	}
	return verify.Required(s.verifier)(documents.NewPublisher(lookup, authorize))
}
