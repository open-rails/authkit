package authhttp

// Application self-registration HTTP surface (#264).
//
// POST /applications/register        — body {"domain": "..."}; the server-side
//   fetch of https://<domain>/.well-known/authkit/application.json IS the
//   domain-control proof. Create-or-reprove idempotency: re-registering the
//   same domain refreshes keys/config from the re-fetched document (boot-time
//   self-heal + rotation-from-root).
// POST /applications/{slug}/rotate   — body {"jws": "<compact>"}; ACME-style
//   per-message JWS signed by a currently-trusted key (convenience rotation).
// POST /applications/{slug}/repoint  — body {"jws": "<compact>"}; signed
//   request + fresh proof of the NEW domain moves the application.
// POST /admin/applications/{slug}/tier — admin act (root:credentials:manage):
//   registered|approved.
//
// No bearer auth on the first three: the domain proof / message signature IS
// the authentication (a stolen bearer can be replayed; a signed message with a
// tight iat window cannot, and registration has no bearer to present yet).

import (
	"errors"
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
	switch {
	case errors.Is(err, authkit.ErrApplicationRegistrationDisabled):
		forbidden(w, ErrApplicationRegistrationDisabled)
	case errors.Is(err, authkit.ErrApplicationDomainInvalid):
		badRequest(w, ErrApplicationDomainInvalid)
	case errors.Is(err, authkit.ErrApplicationDocumentFetchFailed):
		sendErr(w, http.StatusBadGateway, ErrApplicationDocumentFetchFailed)
	case errors.Is(err, authkit.ErrApplicationDocumentInvalid),
		errors.Is(err, authkit.ErrInvalidRemoteApplication),
		errors.Is(err, authkit.ErrReservedIssuer):
		badRequest(w, ErrApplicationDocumentInvalid)
	case errors.Is(err, authkit.ErrApplicationSlugConflict):
		sendErr(w, http.StatusConflict, ErrApplicationSlugConflict)
	case errors.Is(err, authkit.ErrApplicationIssuerConflict):
		sendErr(w, http.StatusConflict, ErrApplicationIssuerConflict)
	case errors.Is(err, authkit.ErrApplicationDomainConflict):
		sendErr(w, http.StatusConflict, ErrApplicationDomainConflict)
	case errors.Is(err, authkit.ErrApplicationNotDomainRooted):
		sendErr(w, http.StatusConflict, ErrApplicationNotDomainRooted)
	case errors.Is(err, authkit.ErrApplicationSignatureStale):
		unauthorized(w, ErrApplicationSignatureStale)
	case errors.Is(err, authkit.ErrApplicationSignatureInvalid):
		unauthorized(w, ErrApplicationSignatureInvalid)
	case errors.Is(err, authkit.ErrApplicationTierInvalid):
		badRequest(w, ErrApplicationTierInvalid)
	case errors.Is(err, authkit.ErrRemoteApplicationNotFound):
		notFound(w, ErrNotFound)
	default:
		serverErr(w, ErrDatabaseError)
	}
}

func (s *Service) handleApplicationRegisterPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLApplicationRegister) {
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Domain) == "" {
		badRequest(w, ErrInvalidRequest)
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

func (s *Service) handleApplicationRotatePOST(w http.ResponseWriter, r *http.Request) {
	s.handleSignedApplicationRequest(w, r, "rotate")
}

func (s *Service) handleApplicationRepointPOST(w http.ResponseWriter, r *http.Request) {
	s.handleSignedApplicationRequest(w, r, "repoint")
}

func (s *Service) handleSignedApplicationRequest(w http.ResponseWriter, r *http.Request, op string) {
	if s.rateLimited(w, r, RLApplicationRotate) {
		return
	}
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("slug")))
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimitedByIdentifier(w, r, RLApplicationRotate, slug) {
		return
	}
	var req struct {
		JWS string `json:"jws"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.JWS) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	switch op {
	case "rotate":
		app, err := s.svc.RotateApplicationSigned(r.Context(), slug, strings.TrimSpace(req.JWS))
		if err != nil {
			s.writeApplicationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"application": applicationJSON(*app)})
	case "repoint":
		reg, err := s.svc.RepointApplicationSigned(r.Context(), slug, strings.TrimSpace(req.JWS))
		if err != nil {
			s.writeApplicationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, registeredApplicationJSON(reg))
	}
}

// handleAdminApplicationTierPOST is the admin approval act: tier
// registered|approved. Gated by root:credentials:manage (see APIRoutes).
func (s *Service) handleAdminApplicationTierPOST(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(strings.TrimSpace(r.PathValue("slug")))
	var req struct {
		Tier string `json:"tier"`
	}
	if err := decodeJSON(r, &req); err != nil || slug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	app, err := s.svc.SetApplicationTier(r.Context(), slug, req.Tier)
	if err != nil {
		s.writeApplicationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"application": applicationJSON(*app)})
}
