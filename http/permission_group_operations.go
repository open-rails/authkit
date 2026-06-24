package authhttp

// Operation handlers for the auto-generated per-persona group-management surface
// (#111, task #15). The caller is already AUTHORIZED (svc.Can passed) by the time
// these run; they decode input, call the public core Service API, and shape the
// JSON response. Group ids never appear here — everything is addressed by
// (persona, instance_slug).

import (
	"errors"
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

// memberRequest is the body for POST /<persona>/<instance_slug>/members. role is
// optional (defaults to the seeded base-membership role).
type memberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// groupMemberAdd assigns a subject (user) a role in the group. The role defaults
// to the base-membership role when omitted. Idempotent at the store layer.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	var body memberRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = core.MemberRoleName
	}
	actor, ok := ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, ErrForbidden)
		return
	}
	// #136: actor-aware assignment enforces capability + no-escalation in core.
	if err := s.svc.AssignGroupRoleAs(r.Context(), actor.UserID, persona, instanceSlug, strings.TrimSpace(body.UserID), core.SubjectKindUser, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       persona,
		"instance_slug": instanceSlug,
		"user_id":       strings.TrimSpace(body.UserID),
		"role":          role,
	})
}

// groupMemberRemove revokes the user's role in the group.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, persona, instanceSlug, userID string) {
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.RemoveGroupSubject(r.Context(), persona, instanceSlug, userID, core.SubjectKindUser); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       persona,
		"instance_slug": instanceSlug,
		"user_id":       userID,
	})
}

// groupMemberRole assigns or replaces the user's single role in the group.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, persona, instanceSlug, userID, role string) {
	if userID == "" || role == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	actor, ok := ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, ErrForbidden)
		return
	}
	// #136: actor-aware assignment enforces capability + no-escalation in core.
	if err := s.svc.AssignGroupRoleAs(r.Context(), actor.UserID, persona, instanceSlug, userID, core.SubjectKindUser, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       persona,
		"instance_slug": instanceSlug,
		"user_id":       userID,
		"role":          role,
	})
}

// groupMembersList lists the members of a group.
//
// The public core Service API does not expose a "list members of a group"
// method (the store's WalkAssignments is per-subject, and surfacing a roster
// would require a new core method). Per the task's constraint to NOT touch core,
// this returns an empty roster with a TODO marker rather than reaching past the
// documented Service API. Wire fully once core grows a group-roster method.
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	members, err := s.svc.ListGroupMembers(r.Context(), persona, instanceSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(members))
	for _, m := range members {
		data = append(data, map[string]any{"subject-id": m.SubjectID, "subject-kind": m.SubjectKind, "role": m.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       persona,
		"instance_slug": instanceSlug,
		"data":          data,
	})
}

// groupRolesList returns the role catalog declared for a persona (always
// available per the generator). This is pure schema data — no DB, no group
// resolution beyond the already-passed authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, persona string) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(persona)
	if !ok {
		notFound(w, ErrNotFound)
		return
	}
	data := make([]map[string]any, 0, len(roles))
	for _, rd := range roles {
		perms := rd.Permissions
		if perms == nil {
			perms = []string{}
		}
		data = append(data, map[string]any{"name": rd.Name, "permissions": perms})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":  "list",
		"persona": persona,
		"data":    data,
	})
}

// handleMeGroupsGET is the cross-persona discovery endpoint: the caller's group
// memberships as {persona, instance_slug, role}.
//
// Listing a subject's memberships across ALL groups requires a core method that
// does not exist on the public Service API (WalkAssignments resolves a SINGLE
// target group's chain, not a global membership scan). Per the task's constraint
// to NOT touch core, this returns an empty list with a TODO rather than adding a
// core store walk. Wire fully once core exposes a per-subject membership listing.
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	groups, err := s.svc.ListSubjectGroups(r.Context(), claims.UserID, core.SubjectKindUser)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		data = append(data, map[string]any{"persona": g.Persona, "instance_slug": g.InstanceSlug, "role": g.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

// handleMePermissionsGET is the permission-introspection endpoint (#421): it
// returns the authenticated subject's effective grant PATTERNS within ONE group
// instance, so a client can gate UI on permission strings (glob-matching with
// authbase.PermMatches, the same matcher the server enforces with) instead of
// re-deriving authority from role slugs. Scoped by ?persona= (default "root") and
// ?instance= (default "" — the singleton root group); a per-instance scope is
// required because perms are persona-namespaced. Globs like `root:*` (held by an
// owner) are returned VERBATIM.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	persona := strings.TrimSpace(r.URL.Query().Get("persona"))
	if persona == "" {
		persona = core.RootPersona
	}
	instance := strings.TrimSpace(r.URL.Query().Get("instance"))
	perms, err := s.svc.ListEffectivePermissions(r.Context(), claims.UserID, core.SubjectKindUser, persona, instance)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "permission_set",
		"persona":       persona,
		"instance_slug": instance,
		"permissions":   perms,
	})
}

// --- api-keys ---------------------------------------------------------------

// apiKeyMintRequest is the body for POST /<persona>/<instance_slug>/api-keys. Role
// is required (the single group role the key holds); resources are optional,
// opaque host-defined scopes.
type apiKeyMintRequest struct {
	Name      string                `json:"name"`
	Role      string                `json:"role"`
	Resources []core.APIKeyResource `json:"resources"`
	ExpiresAt *time.Time            `json:"expires_at"`
}

// groupAPIKeyMint mints a new API key for the group, returning the plaintext
// secret ONCE (it is never recoverable afterward). The created-by attribution is
// the authenticated caller.
func (s *Service) groupAPIKeyMint(w http.ResponseWriter, r *http.Request, persona, instanceSlug, createdBy string) {
	var body apiKeyMintRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	key, secret, err := s.svc.MintAPIKeyWithOptions(r.Context(), persona, instanceSlug, core.APIKeyMintOptions{
		Name:      strings.TrimSpace(body.Name),
		Role:      strings.TrimSpace(body.Role),
		Resources: body.Resources,
		CreatedBy: createdBy,
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          key.ID,
		"key_id":      key.KeyID,
		"name":        key.Name,
		"role":        key.Role,
		"permissions": key.Permissions,
		"resources":   apiKeyResourcesJSON(key.Resources),
		"secret":      secret, // shown ONCE
	})
}

// groupAPIKeyList lists the group's API keys. The secret is NEVER returned here
// (only on mint).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	keys, err := s.svc.ListAPIKeys(r.Context(), persona, instanceSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		m := map[string]any{
			"id":          k.ID,
			"key_id":      k.KeyID,
			"name":        k.Name,
			"role":        k.Role,
			"permissions": k.Permissions,
			"resources":   apiKeyResourcesJSON(k.Resources),
			"created_at":  k.CreatedAt,
		}
		if k.LastUsedAt != nil {
			m["last_used_at"] = k.LastUsedAt
		}
		if k.ExpiresAt != nil {
			m["expires_at"] = k.ExpiresAt
		}
		if k.RevokedAt != nil {
			m["revoked_at"] = k.RevokedAt
		}
		data = append(data, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       persona,
		"instance_slug": instanceSlug,
		"data":          data,
	})
}

// groupAPIKeyRevoke revokes the group's API key by token id (the :key path
// param). 404 if no matching, not-already-revoked key exists in this group.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, persona, instanceSlug, tokenID string) {
	if tokenID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	ok, err := s.svc.RevokeAPIKey(r.Context(), persona, instanceSlug, tokenID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if !ok {
		notFound(w, ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": tokenID})
}

func apiKeyResourcesJSON(rs []core.APIKeyResource) []map[string]any {
	out := make([]map[string]any, 0, len(rs))
	for _, r := range rs {
		out = append(out, map[string]any{"persona": r.Persona, "id": r.ID})
	}
	return out
}

// --- remote-applications ----------------------------------------------------

// remoteAppRegisterRequest is the body for POST
// /<persona>/<instance_slug>/remote-applications. The controlling
// permission_group_id is the addressed group (never request-supplied), so the
// body carries only the issuer/trust-source fields.
type remoteAppRegisterRequest struct {
	Slug           string              `json:"slug"`
	Issuer         string              `json:"issuer"`
	JWKSURI        string              `json:"jwks_uri"`
	Mode           string              `json:"mode"`
	PublicKeys     []core.RemoteAppKey `json:"public_keys"`
	Audiences      []string            `json:"audiences"`
	AllowedOrigins []string            `json:"allowed_origins"`
	Enabled        bool                `json:"enabled"`
}

// groupRemoteAppRegister registers (upserts) a remote_application owned by the
// addressed group. The group's internal id becomes the controlling
// permission_group_id.
func (s *Service) groupRemoteAppRegister(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	var body remoteAppRegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}
	gid, err := s.svc.ResolveGroupIDForSlug(r.Context(), persona, instanceSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	ra, err := s.svc.UpsertRemoteApplication(r.Context(), core.RemoteApplication{
		Slug:              strings.TrimSpace(body.Slug),
		PermissionGroupID: gid,
		Issuer:            strings.TrimSpace(body.Issuer),
		JWKSURI:           strings.TrimSpace(body.JWKSURI),
		Mode:              strings.TrimSpace(body.Mode),
		PublicKeys:        body.PublicKeys,
		Audiences:         body.Audiences,
		AllowedOrigins:    body.AllowedOrigins,
		Enabled:           body.Enabled,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, remoteAppJSON(ra))
}

// groupRemoteAppList lists the remote_applications controlled by the addressed
// group (only this group's — not every group's).
func (s *Service) groupRemoteAppList(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	apps, err := s.svc.ListRemoteApplicationsForGroup(r.Context(), persona, instanceSlug)
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
		"persona":       persona,
		"instance_slug": instanceSlug,
		"data":          data,
	})
}

// groupRemoteAppDelete removes a remote_application. The :app path param is the
// remote_application's slug; it is resolved to its issuer (scoped to this group)
// before deletion so a manager cannot delete another group's issuer.
func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, persona, instanceSlug, slug string) {
	if slug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	gid, err := s.svc.ResolveGroupIDForSlug(r.Context(), persona, instanceSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	ra, err := s.svc.GetRemoteApplicationBySlug(r.Context(), slug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	// Scope check: the issuer must belong to the addressed group.
	if ra.PermissionGroupID != gid {
		notFound(w, ErrNotFound)
		return
	}
	if err := s.svc.DeleteRemoteApplication(r.Context(), ra.Issuer); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "slug": slug})
}

func remoteAppJSON(ra *core.RemoteApplication) map[string]any {
	return map[string]any{
		"id":              ra.ID,
		"slug":            ra.Slug,
		"issuer":          ra.Issuer,
		"jwks_uri":        ra.JWKSURI,
		"mode":            ra.Mode,
		"audiences":       ra.Audiences,
		"allowed_origins": ra.AllowedOrigins,
		"enabled":         ra.Enabled,
	}
}

// --- invite links (#134) -----------------------------------------------------

// inviteLinkCreateRequest is the body for POST /<persona>/<instance_slug>/invites/links.
// role is required; email set => email-bound (defaults single-use); max_uses caps
// redemptions (omit = unlimited shareable / 1 email); expires_in_seconds overrides
// the per-kind default lifetime.
type inviteLinkCreateRequest struct {
	Role             string `json:"role"`
	Email            string `json:"email,omitempty"`
	MaxUses          *int   `json:"max_uses,omitempty"`
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// groupInviteLinkMint mints an invite link; the plaintext code is returned ONCE.
func (s *Service) groupInviteLinkMint(w http.ResponseWriter, r *http.Request, persona, instanceSlug, invitedBy string) {
	var body inviteLinkCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	req := core.CreateGroupInviteLinkRequest{
		Persona:      persona,
		InstanceSlug: instanceSlug,
		Role:         strings.TrimSpace(body.Role),
		Email:        strings.TrimSpace(body.Email),
		MaxUses:      body.MaxUses,
		InvitedBy:    invitedBy,
	}
	if body.ExpiresInSeconds != nil && *body.ExpiresInSeconds > 0 {
		req.ExpiresIn = time.Duration(*body.ExpiresInSeconds) * time.Second
	}
	created, err := s.svc.CreateGroupInviteLink(r.Context(), req)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":   created.ID,
		"code": created.Code, // shown ONCE
		"url":  created.URL,
	})
}

// groupInviteLinkList lists the group's invite links (never returns the code).
func (s *Service) groupInviteLinkList(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	links, err := s.svc.ListGroupInviteLinks(r.Context(), persona, instanceSlug)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(links))
	for _, l := range links {
		m := map[string]any{
			"id":         l.ID,
			"role":       l.Role,
			"invited_by": l.InvitedBy,
			"uses":       l.Uses,
			"created_at": l.CreatedAt,
		}
		if l.Email != "" {
			m["email"] = l.Email
		}
		if l.MaxUses != nil {
			m["max_uses"] = *l.MaxUses
		}
		if l.ExpiresAt != nil {
			m["expires_at"] = l.ExpiresAt
		}
		if l.RevokedAt != nil {
			m["revoked_at"] = l.RevokedAt
		}
		data = append(data, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       persona,
		"instance_slug": instanceSlug,
		"data":          data,
	})
}

// groupInviteLinkRevoke revokes a link by id (the :link path param), scoped to this group.
func (s *Service) groupInviteLinkRevoke(w http.ResponseWriter, r *http.Request, persona, instanceSlug, linkID string) {
	if linkID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.RevokeGroupInviteLink(r.Context(), persona, instanceSlug, linkID); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": linkID})
}

// inviteRedeemRequest is the body for POST /invites/redeem.
type inviteRedeemRequest struct {
	Code string `json:"code"`
}

// handleInviteRedeemPOST redeems an invite-link code for the authenticated caller,
// assigning the link's role. Persona-agnostic: the code resolves to its own group,
// so one endpoint serves every persona.
func (s *Service) handleInviteRedeemPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	var body inviteRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	res, err := s.svc.RedeemGroupInviteLink(r.Context(), strings.TrimSpace(body.Code), claims.UserID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       res.Persona,
		"instance_slug": res.InstanceSlug,
		"role":          res.Role,
	})
}

// writeGroupOpError maps a core group-operation error to a wire response. An
// unknown group / unknown instance_slug / absent invite resolves to 404; an invalid
// role or malformed request to 400; everything else to a 500 database error.
func (s *Service) writeGroupOpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrTwoFAEnrollmentRequired):
		send2FAEnrollmentRequiredError(w)
		return
	case errors.Is(err, core.ErrGroupNotFound),
		errors.Is(err, core.ErrRemoteApplicationNotFound),
		errors.Is(err, core.ErrInviteLinkNotFound):
		notFound(w, ErrNotFound)
		return
	case errors.Is(err, core.ErrInviteEmailMismatch),
		errors.Is(err, core.ErrExternalInvitesDisabled),
		errors.Is(err, core.ErrResourceScopeDenied),
		errors.Is(err, core.ErrInsufficientRoleAuthority),
		errors.Is(err, core.ErrRoleAssignmentEscalation):
		if errors.Is(err, core.ErrResourceScopeDenied) {
			forbidden(w, ErrResourceScopeDenied)
			return
		}
		forbidden(w, ErrForbidden)
		return
	case errors.Is(err, core.ErrInvalidRemoteApplication),
		errors.Is(err, core.ErrReservedIssuer),
		errors.Is(err, core.ErrInviteLinkExpired),
		errors.Is(err, core.ErrInviteLinkExhausted),
		errors.Is(err, core.ErrInviteLinkRevoked):
		badRequest(w, ErrInvalidRequest)
		return
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not assignable"),
		strings.Contains(msg, "invalid_role"),
		strings.Contains(msg, "unknown_role"),
		strings.Contains(msg, "missing_name"),
		strings.Contains(msg, "invalid_invite"),
		strings.Contains(msg, "invalid_resource"),
		strings.Contains(msg, "duplicate_resource"),
		strings.Contains(msg, "invalid_expiry"):
		badRequest(w, ErrInvalidRequest)
	case strings.Contains(msg, "not found"):
		notFound(w, ErrNotFound)
	default:
		serverErr(w, ErrDatabaseError)
	}
}

// customRoleRequest is the body for defining a per-group custom role.
type customRoleRequest struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// groupCustomRoleDefine creates/updates a custom role in the group (custom-role
// personas only). Validation failures (bad perm, cross-persona, persona disallows
// custom roles) are client errors (400); an unknown resource is 404.
func (s *Service) groupCustomRoleDefine(w http.ResponseWriter, r *http.Request, persona, instanceSlug string) {
	var body customRoleRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.DefineGroupCustomRole(r.Context(), persona, instanceSlug, strings.TrimSpace(body.Role), body.Permissions); err != nil {
		if errors.Is(err, core.ErrGroupNotFound) {
			notFound(w, ErrNotFound)
			return
		}
		badRequest(w, ErrInvalidRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"persona":       persona,
		"instance_slug": instanceSlug,
		"role":          strings.TrimSpace(body.Role),
		"permissions":   body.Permissions,
	})
}

// groupCustomRoleDelete removes a custom role from the group.
func (s *Service) groupCustomRoleDelete(w http.ResponseWriter, r *http.Request, persona, instanceSlug, role string) {
	if strings.TrimSpace(role) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.DeleteGroupCustomRole(r.Context(), persona, instanceSlug, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "persona": persona, "instance_slug": instanceSlug, "role": role})
}
