package httpapi

// Remote-application handlers of the group surface.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
)

// remoteAppRegisterRequest is the body for POST
// /groups/{group_id}/remote-applications. The controlling
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
func (s *Service) groupRemoteAppRegister(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
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
	ra, err := s.svc.UpsertRemoteApplication(r.Context(), actor, iam.GroupByID(g.ID), iam.RemoteApplication{
		Slug:       strings.TrimSpace(body.Slug),
		Issuer:     strings.TrimSpace(body.Issuer),
		JWKSURI:    strings.TrimSpace(body.JWKSURI),
		Mode:       iam.RemoteApplicationMode(strings.TrimSpace(body.Mode)),
		PublicKeys: body.PublicKeys,
		Enabled:    enabled,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, remoteAppJSON(ra))
}

// groupRemoteAppList lists one page of the applications the addressed group
// controls (?cursor=&limit=).
func (s *Service) groupRemoteAppList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	page, ok := remoteAppPage(w, r)
	if !ok {
		return
	}
	apps, err := s.svc.RemoteApplications(r.Context(), iam.GroupByID(g.ID), page)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(apps.Items))
	for i := range apps.Items {
		data = append(data, remoteAppJSON(&apps.Items[i]))
	}
	writeList(w, data, apps.Next)
}

// remoteAppPage reads the cursor and limit query parameters of the list route.
func remoteAppPage(w http.ResponseWriter, r *http.Request) (iam.PageRequest, bool) {
	page := iam.PageRequest{Cursor: r.URL.Query().Get("cursor")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("limit"))
			return iam.PageRequest{}, false
		}
		page.Limit = limit
	}
	return page, true
}

// groupRemoteAppDelete removes a remote_application. The :app path param is the
// remote_application's slug; it is resolved to its issuer (scoped to this group)
// before deletion so a manager cannot delete another group's issuer.
func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, slug string) {
	if slug == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.DeleteRemoteApplication(r.Context(), actor, iam.GroupByID(g.ID), slug); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "slug": slug})
}

// groupRemoteAppRole assigns (or replaces) a remote application's single role
// in the group (#263) — the SubjectKindRemoteApplication symmetric of the member-role
// route, gated <persona>:credentials:manage by the generated route table. The
// :app slug must resolve to an application controlled by the addressed group.
func (s *Service) groupRemoteAppRole(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, appSlug, name string) {
	if appSlug == "" || strings.TrimSpace(name) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.svc.PermissionGroupSchema().ParseRole(g.Persona, name)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	app, err := s.svc.GetRemoteApplicationBySlug(r.Context(), appSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, iam.GroupByID(g.ID), []iam.Subject{iam.RemoteApplicationSubject(app.ID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"group_id": g.ID,
		"persona":  g.Persona,
		"app":      appSlug,
		"role":     role.Name(),
	})
}

func remoteAppJSON(ra *iam.RemoteApplication) map[string]any {
	return map[string]any{
		"id":         ra.ID,
		"slug":       ra.Slug,
		"issuer":     ra.Issuer,
		"jwks_uri":   ra.JWKSURI,
		"mode":       ra.Mode,
		"enabled":    ra.Enabled,
		"tier":       ra.Tier,
		"trust_root": ra.TrustRoot,
	}
}
