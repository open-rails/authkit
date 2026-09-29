package httpapi

// ak#260: the mounted published-document surface. AuthKit owns the store, the
// publish lifecycle (documents.Service), and this route; reader authorization
// is CONFIG (Config.Documents.Readers) — never a host-written callback.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// documentsHandler builds the publication handler over every wired provider.
// Authorization: the request must verify as a remote application pinned by
// Config.Documents.Readers (id, proven domain, or root-registered issuer —
// never the slug, #296) at the approved tier unless AllowRegisteredTier. The
// verifier middleware authenticates; the publisher's authorize callback checks
// the resulting claims.
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
	cfg := s.settings.Documents
	byID, byDomain, byIssuer := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, reader := range cfg.Readers {
		switch {
		case reader.ID != "":
			byID[reader.ID] = true
		case reader.Domain != "":
			byDomain[reader.Domain] = true
		case reader.Issuer != "":
			byIssuer[reader.Issuer] = true
		}
	}
	authorize := func(r *http.Request) error {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok || claims.PrincipalKind() != iam.PrincipalKindRemoteApplication {
			return documents.ErrUnauthorized
		}
		if claims.RemoteApplicationTier != iam.ApplicationTierApproved && !cfg.AllowRegisteredTier {
			return documents.ErrUnauthorized
		}
		switch {
		case byID[claims.RemoteApplicationID]:
		case claims.RemoteApplicationTrustRoot == iam.ApplicationTrustRootDomain &&
			byDomain[strings.ToLower(claims.RemoteApplicationDomain)]:
		case claims.RemoteApplicationTrustRoot == iam.ApplicationTrustRootManual &&
			iam.Persona(claims.PermissionGroupPersona) == iam.RootPersona && byIssuer[claims.Issuer]:
		default:
			return documents.ErrUnauthorized
		}
		return nil
	}
	return verify.Required(s.verifier)(documents.NewPublisher(lookup, authorize))
}
