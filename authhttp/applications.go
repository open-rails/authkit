package authhttp

// Application self-registration HTTP surface (#264).
//
// POST /applications/register — body {"domain": "..."}; the server-side fetch
// of https://<domain>/.well-known/authkit/application.json IS the
// domain-control proof. Create-or-reprove idempotency: re-registering the same
// domain refreshes keys/config from the re-fetched document (boot-time
// self-heal + rotation-from-root). No bearer auth: the domain proof IS the
// authentication, and registration has no bearer to present yet.

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
)

func applicationJSON(app authkit.RemoteApplication) map[string]any {
	m := map[string]any{
		"id":                app.ID,
		"slug":              app.Slug,
		"display_name":      app.DisplayName,
		"issuer":            app.Issuer,
		"mode":              app.Mode,
		"jwks_uri":          app.JWKSURI,
		"tier":              app.Tier,
		"trust_root":        app.TrustRoot,
		"domain":            app.Domain,
		"enabled":           app.Enabled,
		"document_endpoint": app.DocumentEndpoint,
		"created_at":        app.CreatedAt,
		"updated_at":        app.UpdatedAt,
	}
	if !app.RootVerifiedAt.IsZero() {
		m["root_verified_at"] = app.RootVerifiedAt
	}
	return m
}

func registeredApplicationJSON(reg *authkit.RegisteredApplication) map[string]any {
	return map[string]any{
		"application": applicationJSON(reg.Application),
		"org": map[string]any{
			"persona":       reg.OrgPersona,
			"instance_slug": reg.OrgInstanceSlug,
		},
		"created": reg.Created,
	}
}

func (s *Service) writeApplicationError(w http.ResponseWriter, err error) {
	writeError(w, remap(err, notFoundCodes, applicationCodes))
}

// applicationCodes: the document-shape refusals answer one code.
var applicationCodes = map[error]authkit.Code{
	authkit.ErrInvalidRemoteApplication: authkit.CodeApplicationDocumentInvalid,
	authkit.ErrReservedIssuer:           authkit.CodeApplicationDocumentInvalid,
}

func (s *Service) handleApplicationRegisterPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Domain) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	// Per-domain limit on top of per-IP: many IPs hammering one domain (or one
	// IP cycling domains) both hit a wall.
	if s.rateLimitedByIdentifier(w, r, RLApplicationRegister, req.Domain) {
		return
	}
	reg, err := s.svc.RegisterApplicationFromDomain(r.Context(), req.Domain)
	if err != nil {
		s.writeApplicationError(w, err)
		return
	}
	status := http.StatusOK
	if reg.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, registeredApplicationJSON(reg))
}
