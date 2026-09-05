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

	"github.com/open-rails/authkit/verify"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

// memberRequest is the body for POST /<persona>/<instance_slug>/members.
type memberRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// groupMemberAdd assigns a subject (user) a role in the group. Idempotent at the
// store layer.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	var body memberRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	userID := strings.TrimSpace(body.UserID)
	email := embedded.NormalizeEmail(body.Email)
	if (userID == "") == (email == "") {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	role := authkit.Role(strings.TrimSpace(body.Role))
	if role == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if email != "" {
		if err := embedded.ValidateEmail(email); err != nil {
			writeError(w, err)
			return
		}
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	if email != "" {
		u, err := s.svc.GetUserByEmail(r.Context(), email)
		if errors.Is(err, pgx.ErrNoRows) {
			u = nil
		} else if err != nil {
			s.logInternalError(r, "permission_group_member_add", "lookup_email", "database_error", err)
			serverErr(w, authkit.CodeDatabaseError)
			return
		}
		if u == nil {
			if s.rateLimited(w, r, RLInviteCreate) || s.rateLimitedByIdentifier(w, r, RLInviteCreate, email) {
				return
			}
			// #147 register+join: mint ONE role-carrying account-registration invite.
			// Consuming the code authorizes the stranger's registration AND grants this
			// role on consume — one link covers register + join. Authorized by THIS
			// group's members:manage (the role-carrying create path), which does not
			// grant general root:users:invite authority.
			invite, err := s.svc.CreateAccountRegistrationInvite(r.Context(), authkit.CreateAccountRegistrationInviteRequest{
				Email:        email,
				InvitedBy:    actor.UserID,
				Persona:      group.Persona,
				InstanceSlug: group.Instance,
				Role:         role,
			})
			if err != nil {
				s.writeGroupOpError(w, err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{
				"ok":            true,
				"persona":       group.Persona,
				"instance_slug": group.Instance,
				"email":         email,
				"role":          role,
				"invited":       true,
				"invite": map[string]any{
					"id":   invite.ID,
					"code": invite.Code,
					"url":  invite.URL,
				},
			})
			return
		}
		userID = u.ID
	}
	// #136: actor-aware assignment enforces capability + no-escalation in embedded.
	if err := s.svc.AssignGroupRoleAs(r.Context(), actor.UserID, group, authkit.UserSubject(userID), role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"user_id":       userID,
		"role":          role,
	})
}

// groupMemberRemove revokes the user's role in the group.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, userID string) {
	if userID == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	// #136: actor-aware removal enforces no-escalation across every role the
	// target holds — a non-owner cannot strip an owner's roles.
	if err := s.svc.RemoveGroupSubjectAs(r.Context(), actor.UserID, group, authkit.UserSubject(userID)); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"user_id":       userID,
	})
}

// groupMemberRole assigns or replaces the user's single role in the group.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, userID string, role authkit.Role) {
	if userID == "" || role == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	// #136: actor-aware assignment enforces capability + no-escalation in embedded.
	if err := s.svc.AssignGroupRoleAs(r.Context(), actor.UserID, group, authkit.UserSubject(userID), role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"user_id":       userID,
		"role":          role,
	})
}

// groupMembersList lists the role assignments in a group.
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	members, err := s.svc.ListGroupMembers(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(members))
	for _, m := range members {
		data = append(data, map[string]any{"subject_id": m.SubjectID, "subject_kind": m.SubjectKind, "role": m.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"data":          data,
	})
}

// groupRolesList returns the role catalog declared for a persona (always
// available per the generator). This is pure schema data — no DB, no group
// resolution beyond the already-passed authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, persona authkit.Persona) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(persona)
	if !ok {
		notFound(w, authkit.CodeNotFound)
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
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	groups, err := s.svc.ListSubjectGroups(r.Context(), authkit.UserSubject(claims.UserID))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		// #269: the caller's OWN memberships carry the group uuid — they have
		// already passed the only authorization that could gate it, and this is
		// the discovery path a client uses to learn what it belongs to.
		data = append(data, map[string]any{"group_id": g.GroupID, "persona": g.Persona, "instance_slug": g.InstanceSlug, "role": g.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

// handleMePermissionsGET is the permission-introspection endpoint (#421): it
// returns the authenticated subject's effective grant PATTERNS within ONE group
// instance, so a client can gate UI on permission strings (glob-matching with
// authkit.Perm.Matches, the same matcher the server enforces with) instead of
// re-deriving authority from role slugs. Scoped by ?persona= (default "root") and
// ?instance= (default "" — the singleton root group); a per-instance scope is
// required because perms are persona-namespaced. Globs like `root:*` (held by an
// owner) are returned VERBATIM.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	group := authkit.GroupRef{
		Persona:  authkit.Persona(strings.TrimSpace(r.URL.Query().Get("persona"))),
		Instance: strings.TrimSpace(r.URL.Query().Get("instance")),
	}
	if group.Persona == "" {
		group.Persona = authkit.RootPersona
	}
	perms, err := s.svc.ListEffectivePermissions(r.Context(), authkit.UserSubject(claims.UserID), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "permission_set",
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"permissions":   perms,
	})
}

// --- api-keys ---------------------------------------------------------------

// apiKeyMintRequest is the body for POST /<persona>/<instance_slug>/api-keys. Role
// is required (the single group role the key holds); the key's scope is the
// addressed permission-group instance plus that role's permissions.
type apiKeyMintRequest struct {
	Name      string     `json:"name"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// groupAPIKeyMint mints a new API key for the group, returning the plaintext
// secret ONCE (it is never recoverable afterward). The created-by attribution is
// the authenticated caller.
func (s *Service) groupAPIKeyMint(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, createdBy string) {
	var body apiKeyMintRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	key, secret, err := s.svc.MintAPIKeyWithOptions(r.Context(), group, authkit.APIKeyMintOptions{
		Name:      strings.TrimSpace(body.Name),
		Role:      authkit.Role(strings.TrimSpace(body.Role)),
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
		"secret":      secret, // shown ONCE
	})
}

// groupAPIKeyList lists the group's API keys. The secret is NEVER returned here
// (only on mint).
func (s *Service) groupAPIKeyList(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	keys, err := s.svc.ListAPIKeys(r.Context(), group)
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
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"data":          data,
	})
}

// groupAPIKeyRevoke revokes the group's API key by token id (the :key path
// param). 404 if no matching, not-already-revoked key exists in this group.
func (s *Service) groupAPIKeyRevoke(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, tokenID string) {
	if tokenID == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	ok, err := s.svc.RevokeAPIKey(r.Context(), group, tokenID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	if !ok {
		notFound(w, authkit.CodeNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": tokenID})
}

// --- remote-applications ----------------------------------------------------

// remoteAppRegisterRequest is the body for POST
// /<persona>/<instance_slug>/remote-applications. The controlling
// permission_group_id is the addressed group (never request-supplied), so the
// body carries only the issuer/trust-source fields.
type remoteAppRegisterRequest struct {
	Slug       string                 `json:"slug"`
	Issuer     string                 `json:"issuer"`
	JWKSURI    string                 `json:"jwks_uri"`
	Mode       string                 `json:"mode"`
	PublicKeys []authkit.RemoteAppKey `json:"public_keys"`
	// Enabled is a pointer so an omitted field ("enabled" absent) is
	// distinguishable from an explicit false. Omitted defaults to true on this
	// register/upsert endpoint; an explicit false still disables the issuer.
	Enabled *bool `json:"enabled,omitempty"`
}

// groupRemoteAppRegister registers (upserts) a remote_application owned by the
// addressed group. The group's internal id becomes the controlling
// permission_group_id.
func (s *Service) groupRemoteAppRegister(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	var body remoteAppRegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	gid, err := s.svc.ResolveGroupIDForSlug(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	// Default to enabled when the field is omitted; preserve an explicit
	// true/false. A plain bool would collapse "omitted" into false and silently
	// disable an existing issuer on any partial re-register (e.g. rotating keys).
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	ra, err := s.svc.UpsertRemoteApplication(r.Context(), authkit.RemoteApplication{
		Slug:              strings.TrimSpace(body.Slug),
		PermissionGroupID: gid,
		Issuer:            strings.TrimSpace(body.Issuer),
		JWKSURI:           strings.TrimSpace(body.JWKSURI),
		Mode:              strings.TrimSpace(body.Mode),
		PublicKeys:        body.PublicKeys,
		Enabled:           enabled,
	})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, remoteAppJSON(ra))
}

// groupRemoteAppList lists the remote_applications controlled by the addressed
// group (only this group's — not every group's).
func (s *Service) groupRemoteAppList(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
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
func (s *Service) groupRemoteAppDelete(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, slug string) {
	if slug == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	gid, err := s.svc.ResolveGroupIDForSlug(r.Context(), group)
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
		notFound(w, authkit.CodeNotFound)
		return
	}
	if err := s.svc.DeleteRemoteApplication(r.Context(), ra.Issuer); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "slug": slug})
}

// groupRemoteAppRole assigns (or replaces) a remote application's single role
// in the group (#263) — the SubjectKindRemoteApp symmetric of the member-role
// route, gated <persona>:credentials:manage by the generated route table. The
// :app slug must resolve to an application controlled by the addressed group.
func (s *Service) groupRemoteAppRole(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, appSlug string, role authkit.Role) {
	if appSlug == "" || role == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
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

func remoteAppJSON(ra *authkit.RemoteApplication) map[string]any {
	return map[string]any{
		"id":       ra.ID,
		"slug":     ra.Slug,
		"issuer":   ra.Issuer,
		"jwks_uri": ra.JWKSURI,
		"mode":     ra.Mode,
		"enabled":  ra.Enabled,
	}
}

// --- invite links (#134) -----------------------------------------------------

// inviteLinkCreateRequest is the body for POST /<persona>/<instance_slug>/invites/links.
// role is required; expires_in_seconds overrides the default lifetime.
type inviteLinkCreateRequest struct {
	Role             string `json:"role"`
	ExpiresInSeconds *int64 `json:"expires_in_seconds,omitempty"`
}

// groupInviteLinkMint mints an invite link; the plaintext code is returned ONCE.
func (s *Service) groupInviteLinkMint(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, invitedBy string) {
	if s.rateLimited(w, r, RLInviteCreate) {
		return
	}
	var body inviteLinkCreateRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	req := authkit.CreateGroupInviteLinkRequest{
		Persona:      group.Persona,
		InstanceSlug: group.Instance,
		Role:         authkit.Role(strings.TrimSpace(body.Role)),
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
func (s *Service) groupInviteLinkList(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	links, err := s.svc.ListGroupInviteLinks(r.Context(), group)
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
			"created_at": l.CreatedAt,
		}
		if l.RedeemedAt != nil {
			m["redeemed_at"] = l.RedeemedAt
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
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"data":          data,
	})
}

// groupInviteLinkRevoke revokes a link by id (the :link path param), scoped to this group.
func (s *Service) groupInviteLinkRevoke(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, linkID string) {
	if linkID == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	if err := s.svc.RevokeGroupInviteLink(r.Context(), group, linkID); err != nil {
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
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, authkit.CodeNotAuthenticated)
		return
	}
	var body inviteRedeemRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Code) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
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

// writeGroupOpError answers a group-operation failure: the 2FA-enrollment
// refusal carries the enrollment metadata, everything else is the catalog's
// status and code through notFoundCodes/groupOpCodes.
func (s *Service) writeGroupOpError(w http.ResponseWriter, err error) {
	if errors.Is(err, authkit.ErrTwoFAEnrollmentRequired) {
		s.send2FAEnrollmentRequiredError(w)
		return
	}
	writeError(w, remap(err, notFoundCodes, groupOpCodes))
}

// groupOpCodes: where a group operation's wire code differs from the catalog
// — one forbidden and one invalid_request per family, and the last-owner
// refusal (#193: unsafe, not unauthorised, so 409).
var groupOpCodes = map[error]authkit.Code{
	authkit.ErrCannotRemoveLastAdminRole:     authkit.CodeCannotRemoveLastOwner,
	authkit.ErrExternalInvitesDisabled:       authkit.CodeForbidden,
	authkit.ErrInsufficientRoleAuthority:     authkit.CodeForbidden,
	authkit.ErrRoleAssignmentEscalation:      authkit.CodeForbidden,
	authkit.ErrInvalidRemoteApplication:      authkit.CodeInvalidRequest,
	authkit.ErrReservedIssuer:                authkit.CodeInvalidRequest,
	authkit.ErrInviteLinkExpired:             authkit.CodeInvalidRequest,
	authkit.ErrInviteLinkRevoked:             authkit.CodeInvalidRequest,
	authkit.ErrRoleNotAssignable:             authkit.CodeInvalidRequest,
	authkit.ErrInvalidRole:                   authkit.CodeInvalidRequest,
	authkit.ErrUnknownRole:                   authkit.CodeInvalidRequest,
	authkit.ErrMissingName:                   authkit.CodeInvalidRequest,
	authkit.ErrInvalidInvite:                 authkit.CodeInvalidRequest,
	authkit.ErrInvalidExpiry:                 authkit.CodeInvalidRequest,
	authkit.ErrUnknownGroupPersona:           authkit.CodeInvalidRequest,
	authkit.ErrCustomRolesNotSupported:       authkit.CodeInvalidRequest,
	authkit.ErrCustomRoleNameInvalid:         authkit.CodeInvalidRequest,
	authkit.ErrCustomRoleIsCatalogRole:       authkit.CodeInvalidRequest,
	authkit.ErrCustomRoleGrantCrossPersona:   authkit.CodeInvalidRequest,
	authkit.ErrCustomRoleGrantOutsideCatalog: authkit.CodeInvalidRequest,
}

// customRoleRequest is the body for defining a per-group custom role.
// RequiresMFA (#247) mirrors RoleDef.RequiresMFA for catalog roles: a custom
// role granting sensitive perms can require MFA on the same assignment/redeem
// gate.
type customRoleRequest struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	RequiresMFA bool     `json:"requires_mfa,omitempty"`
}

// groupCustomRoleDefine creates/updates a custom role in the group (custom-role
// personas only). #247 SECURITY: redefining an existing role is a deferred
// grant to every current holder, so this requires the SAME actor-authz
// (capability + no-escalation, covering old ∪ new grants) as a direct role
// assignment — DefineGroupCustomRole enforces it. Validation failures (bad
// perm, cross-persona, persona disallows custom roles) are client errors (400);
// an unknown resource is 404; an escalation attempt is 403.
func (s *Service) groupCustomRoleDefine(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	var body customRoleRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	role := authkit.Role(strings.TrimSpace(body.Role))
	if err := s.svc.DefineGroupCustomRole(r.Context(), actor.UserID, group, authkit.CustomRoleDef{Role: role, Permissions: body.Permissions, RequiresMFA: body.RequiresMFA}); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"persona":       group.Persona,
		"instance_slug": group.Instance,
		"role":          role,
		"permissions":   body.Permissions,
		"requires_mfa":  body.RequiresMFA,
	})
}

// groupCustomRoleDelete removes a custom role from the group. #247 SECURITY:
// deleting a role is a deferred REVOKE from every current holder, gated by the
// same actor-authz as define.
func (s *Service) groupCustomRoleDelete(w http.ResponseWriter, r *http.Request, group authkit.GroupRef, role authkit.Role) {
	if role == "" {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	actor, ok := verify.ClaimsFromContext(r.Context())
	if !ok || actor.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	if err := s.svc.DeleteGroupCustomRole(r.Context(), actor.UserID, group, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "persona": group.Persona, "instance_slug": group.Instance, "role": role})
}

// groupInstanceDescriptor is the #269 instance-identity read
// (GET /<persona>/{instance_slug}), gated by <persona>:settings:read — the read
// symmetric of the #264 PATCH. It answers with the instance's own uuid, which is
// the JOIN KEY a host needs to carry the group into its own (or a sibling
// service's) ledger; every route stays slug-addressed, so the id is knowable
// here and an address nowhere. A tombstoned slug forwards, and the descriptor
// reports the group's CURRENT live slug — so a caller holding an old reference
// learns the new one in the same call.
func (s *Service) groupInstanceDescriptor(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	inst, err := s.svc.GroupInstanceForSlug(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	state, err := s.svc.GroupNamingState(r.Context(), inst.ID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"naming":        state,
		"ok":            true,
		"group_id":      inst.ID,
		"persona":       inst.Persona,
		"instance_slug": inst.InstanceSlug,
		"display_name":  inst.DisplayName,
	})
}

// groupUpdate is the #264 group-settings surface (PATCH /<persona>/{instance_slug}):
// display-name changes and slug renames, gated by <persona>:settings:manage
// (the owner holds it via the wildcard). The captured UUID is retained through
// authorization, slug rename and display-name mutation in one transaction.
func (s *Service) groupUpdate(w http.ResponseWriter, r *http.Request, group authkit.GroupRef) {
	var req struct {
		Slug        *string `json:"slug"`
		DisplayName *string `json:"display_name"`
	}
	if err := decodeJSON(r, &req); err != nil || (req.Slug == nil && req.DisplayName == nil) {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		forbidden(w, authkit.CodeForbidden)
		return
	}
	// #264 anti-squat velocity: a slug rename is a CLAIM — capped per IP and
	// per user (authkit owns anti-spam velocity; cost gates are the host's).
	if req.Slug != nil {
		if s.rateLimited(w, r, RLGroupSettings) || s.rateLimitedByIdentifier(w, r, RLGroupSettings, claims.UserID) {
			return
		}
	}
	if req.DisplayName != nil && len(*req.DisplayName) > 256 {
		badRequest(w, authkit.CodeInvalidRequest)
		return
	}
	inst, err := s.svc.GroupInstanceForSlug(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	updated, err := s.svc.UpdateGroupInstanceAs(r.Context(), claims.UserID, inst.ID, authkit.GroupInstanceUpdate{Slug: req.Slug, DisplayName: req.DisplayName})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	state, err := s.svc.GroupNamingState(r.Context(), updated.ID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group_id": updated.ID, "persona": updated.Persona, "instance_slug": updated.InstanceSlug, "display_name": updated.DisplayName, "naming": state})
}
