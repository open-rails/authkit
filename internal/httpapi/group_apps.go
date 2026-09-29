package httpapi

// Remote-application handlers of the generated per-persona group surface.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// remoteAppRegisterRequest is the body for POST
// /<persona>/<instance_slug>/remote-applications. The controlling
// permission_group_id is the addressed group (never request-supplied), so the
// body carries only the issuer/trust-source fields.
type remoteAppRegisterRequest struct {
	Slug       string                     `json:"slug"`
	Issuer     string                     `json:"issuer"`
	JWKSURI    string                     `json:"jwks_uri"`
	Mode       string                     `json:"mode"`
	PublicKeys []iam.RemoteApplicationKey `json:"public_keys"`
	// Enabled is a pointer so an omitted field ("enabled" absent) is
	// distinguishable from an explicit false. Omitted defaults to true on this
	// register/upsert endpoint; an explicit false still disables the issuer.
	Enabled *bool `json:"enabled,omitempty"`
}

// groupRemoteAppRegister registers (upserts) a remote_application owned by the
// addressed group. The group's internal id becomes the controlling
// permission_group_id.
func (s *Service) groupRemoteAppRegister(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	var body remoteAppRegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// Default to enabled when the field is omitted; preserve an explicit
	// true/false. A plain bool would collapse "omitted" into false and silently
	// disable an existing issuer on any partial re-register (e.g. rotating keys).
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	ra, err := s.svc.UpsertRemoteApplicationForActor(r.Context(), actor, group, iam.RemoteApplication{
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
func (s *Service) groupRemoteAppList(w http.ResponseWriter, r *http.Request, group iam.GroupRef, _ iam.Actor) {
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
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"data":          data,
	})
}

// groupRemoteAppDelete removes a remote_application. The :app path param is the
// remote_application's slug; it is resolved to its issuer (scoped to this group)
// before deletion so a manager cannot delete another group's issuer.
func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, slug string) {
	if slug == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.DeleteRemoteApplicationForActor(r.Context(), actor, group, slug); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "slug": slug})
}

// groupRemoteAppRole assigns (or replaces) a remote application's single role
// in the group (#263) — the SubjectKindRemoteApplication symmetric of the member-role
// route, gated <persona>:credentials:manage by the generated route table. The
// :app slug must resolve to an application controlled by the addressed group.
func (s *Service) groupRemoteAppRole(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, appSlug string, role iam.Role) {
	role = iam.Role(strings.TrimSpace(string(role)))
	if appSlug == "" || role == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	app, err := s.svc.GetRemoteApplicationBySlug(r.Context(), appSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, group, []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
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
