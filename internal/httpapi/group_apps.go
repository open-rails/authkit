package httpapi

// Remote-application handlers of the generated per-persona group surface.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// remoteAppRegisterRequest is the body for POST
// /<persona>/<instance_slug>/remote-applications. The controlling
// permission_group_id is the addressed group (never request-supplied), so the
// body carries only the issuer/trust-source fields.
type remoteAppRegisterRequest struct {
	Slug       string             `json:"slug"`
	Issuer     string             `json:"issuer"`
	JWKSURI    string             `json:"jwks_uri"`
	Mode       string             `json:"mode"`
	PublicKeys []iam.RemoteAppKey `json:"public_keys"`
	// Enabled is a pointer so an omitted field ("enabled" absent) is
	// distinguishable from an explicit false. Omitted defaults to true on this
	// register/upsert endpoint; an explicit false still disables the issuer.
	Enabled *bool `json:"enabled,omitempty"`
}

// groupRemoteAppRegister registers (upserts) a remote_application owned by the
// addressed group. The group's internal id becomes the controlling
// permission_group_id.
func (s *Service) groupRemoteAppRegister(w http.ResponseWriter, r *http.Request, group iam.GroupRef) {
	var body remoteAppRegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok {
		forbidden(w, iam.CodeForbidden)
		return
	}
	// Default to enabled when the field is omitted; preserve an explicit
	// true/false. A plain bool would collapse "omitted" into false and silently
	// disable an existing issuer on any partial re-register (e.g. rotating keys).
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	ra, err := s.svc.UpsertRemoteApplicationFromClaims(r.Context(), claims, group, iam.RemoteApplication{
		Slug:       strings.TrimSpace(body.Slug),
		Issuer:     strings.TrimSpace(body.Issuer),
		JWKSURI:    strings.TrimSpace(body.JWKSURI),
		Mode:       strings.TrimSpace(body.Mode),
		PublicKeys: body.PublicKeys,
		Enabled:    enabled,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, remoteAppJSON(ra))
}

// groupRemoteAppList lists the remote_applications controlled by the addressed
// group (only this group's — not every group's).
func (s *Service) groupRemoteAppList(w http.ResponseWriter, r *http.Request, group iam.GroupRef) {
	apps, err := s.svc.ListRemoteApplicationsForGroup(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(apps))
	for i := range apps {
		data = append(data, remoteAppJSON(&apps[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"data":          data,
	})
}

// groupRemoteAppDelete removes a remote_application. The :app path param is the
// remote_application's slug; it is resolved to its issuer (scoped to this group)
// before deletion so a manager cannot delete another group's issuer.
func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, group iam.GroupRef, slug string) {
	if slug == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok {
		forbidden(w, iam.CodeForbidden)
		return
	}
	if err := s.svc.DeleteRemoteApplicationFromClaims(r.Context(), claims, group, slug); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "slug": slug})
}

// groupRemoteAppRole assigns (or replaces) a remote application's single role
// in the group (#263) — the SubjectKindRemoteApp symmetric of the member-role
// route, gated <persona>:credentials:manage by the generated route table. The
// :app slug must resolve to an application controlled by the addressed group.
func (s *Service) groupRemoteAppRole(w http.ResponseWriter, r *http.Request, group iam.GroupRef, appSlug string, role iam.Role) {
	role = iam.Role(strings.TrimSpace(string(role)))
	if appSlug == "" || role == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, iam.CodeForbidden)
		return
	}
	// Actor-aware assignment: capability (credentials:manage) + no-escalation.
	if err := s.svc.AssignRemoteApplicationRoleAs(r.Context(), actor.UserID, group, appSlug, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"app":           appSlug,
		"role":          role,
	})
}

func remoteAppJSON(ra *iam.RemoteApplication) map[string]any {
	return map[string]any{
		"id":       ra.ID,
		"slug":     ra.Slug,
		"issuer":   ra.Issuer,
		"jwks_uri": ra.JWKSURI,
		"mode":     ra.Mode,
		"enabled":  ra.Enabled,
	}
}
