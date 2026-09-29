package httpapi

// ak#260: the mounted published-document surface. AuthKit owns the store, the
// publish lifecycle (Auth.PublishDocument) and this route; reader
// authorization is config (Config.Documents.Readers), never a host callback.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// documentsHandler serves every stored document by digest.
// Authorization: the request must verify as a remote application pinned by
// Config.Documents.Readers (id, proven domain, or root-registered issuer —
// never the slug, #296) at the approved tier unless AllowRegisteredTier. The
// verifier middleware authenticates; the publisher's authorize callback checks
// the resulting claims.
func (s *Service) documentsHandler() http.Handler {
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
		claims, _ := verify.ClaimsFromContext(r.Context())
		if actor, ok := verify.ActorFromClaims(claims); !ok || actor.Kind() != iam.ActorRemoteApplication {
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
			claims.PermissionGroupPersona == iam.RootPersona.String() && byIssuer[claims.Issuer]:
		default:
			return documents.ErrUnauthorized
		}
		return nil
	}
	return verify.Required(s.verifier)(documents.NewPublisher(s.svc.LookupDocument, authorize))
}
