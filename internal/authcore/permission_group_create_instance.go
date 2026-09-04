package authcore

// Generated persona-instance CREATION (#263): the core policy behind
// POST /<persona>. Per-persona config (InstanceCreationDef) declares the slug
// pattern and the reserved-slug list + escalation role; the host cost gate is
// the MayCreateInstance admission seam (WithInstanceAdmission); velocity limits
// (per-IP + per-user) are enforced by the HTTP layer. Creation is idempotent
// for existing members: re-creating a slug you already belong to returns the
// group instead of a conflict (bootstrap re-runs).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// Sentinel aliases (#263).
var (
	// ErrGroupSlugReserved: the slug is on the persona's reserved list and the
	// caller does not hold the escalation role.
	ErrGroupSlugReserved = authkit.ErrGroupSlugReserved
	// ErrGroupCreationRefused: the host admission seam refused the creation.
	ErrGroupCreationRefused = authkit.ErrGroupCreationRefused
)

// CreateInstanceResult reports a generated-creation outcome. Created is false
// when the slug already existed and the caller is a member (idempotent return).
type CreateInstanceResult struct {
	// GroupID is the new (or idempotently returned) instance's uuid (#269). It
	// is populated on BOTH outcomes: the idempotent re-run is the bootstrap
	// path, so an id only on Created=true would leave the re-runner with
	// nothing. Empty only on error.
	GroupID      string
	InstanceSlug string
	Created      bool
}

// MayCreateInstance consults the host admission seam (#263). A nil predicate
// allows; a predicate error is wrapped as ErrGroupCreationRefused. The seam
// sees the normalized slug (#269) so a host can refuse a specific namespace
// outright, not merely price the attempt.
func (s *Service) MayCreateInstance(ctx context.Context, persona, instanceSlug, subject string) error {
	if s.instanceAdmission == nil {
		return nil
	}
	if err := s.instanceAdmission(ctx, persona, instanceSlug, subject); err != nil {
		return fmt.Errorf("%w: %w", ErrGroupCreationRefused, err)
	}
	return nil
}

// CreateInstanceForSubject is the #263 creation path: validate the slug against
// the persona's creation config, gate reserved slugs on the root escalation
// role, consult the host admission seam, then create the group with ownerUserID
// seeded as owner. If the slug is already held and the caller is a member of
// that group, it returns Created=false instead of a conflict.
func (s *Service) CreateInstanceForSubject(ctx context.Context, persona, instanceSlug, displayName, ownerUserID string) (CreateInstanceResult, error) {
	var out CreateInstanceResult
	if err := s.requirePG(); err != nil {
		return out, err
	}
	sch := s.groupSchemaOrDefault()
	persona = strings.TrimSpace(persona)
	slug := strings.ToLower(strings.TrimSpace(instanceSlug))
	ownerUserID = strings.TrimSpace(ownerUserID)
	out.InstanceSlug = slug

	def, ok := sch.CreationDef(persona)
	if !ok || !def.Enabled {
		return out, fmt.Errorf("group persona %q does not allow generated instance creation: %w", persona, authkit.ErrUnknownGroupPersona)
	}
	if ownerUserID == "" {
		return out, ErrInsufficientRoleAuthority
	}
	if err := s.authorizeSlugClaim(ctx, sch, persona, slug, ownerUserID); err != nil {
		return out, err
	}

	if err := s.admitName(ctx, authkit.NameAdmissionRequest{OwnerKind: "group", Persona: persona, ActorID: ownerUserID, RequestedName: slug, Operation: authkit.NameCreate}); err != nil {
		return out, err
	}

	// Host cost gate (anti-squat split: velocity is authkit's, cost is the host's).
	if err := s.MayCreateInstance(ctx, persona, slug, ownerUserID); err != nil {
		return out, err
	}

	gid, err := s.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{
		Persona:        persona,
		InstanceSlug:   slug,
		DisplayName:    strings.TrimSpace(displayName),
		OwnerSubjectID: ownerUserID,
	})
	if err == nil {
		out.GroupID = gid
		out.Created = true
		return out, nil
	}
	// Create-or-return-if-member idempotency: a live-slug collision (unique
	// violation) or a tombstoned slug both surface as "taken" — but if the
	// caller is already a member of the LIVE group holding the slug, the
	// creation is a re-run and succeeds idempotently. The re-run reports the
	// EXISTING group's id (#269) — it is the bootstrap path, and a caller that
	// learns nothing from a re-run has to be able to create to function.
	if isUniqueViolation(err, "permission_groups_persona_instance_uidx") || errors.Is(err, ErrGroupSlugTaken) {
		existing, member, merr := s.subjectMemberOfGroup(ctx, ownerUserID, persona, slug)
		if merr != nil {
			return out, merr
		}
		if member {
			out.GroupID = existing
			return out, nil // Created=false
		}
		return out, ErrGroupSlugTaken
	}
	return out, err
}

// authorizeSlugClaim is the single gate for a user claiming an instance slug
// (creation and rename, #263/#292): the built-in slug rule, the persona's
// SlugPattern, and reserved slugs, which only a holder of the configured
// root-group escalation role may take; with no role configured they are never
// claimable.
func (s *Service) authorizeSlugClaim(ctx context.Context, sch *GroupSchema, persona, slug, actorUserID string) error {
	if err := validateGroupInstanceSlug(persona, slug); err != nil {
		return fmt.Errorf("%w: %w", authkit.ErrGroupSlugInvalid, err)
	}
	if !sch.creationSlugAllowed(persona, slug) {
		return fmt.Errorf("resource slug %q does not match the %q creation slug pattern: %w", slug, persona, authkit.ErrGroupSlugInvalid)
	}
	def, _ := sch.CreationDef(persona)
	if slugReserved(def.ReservedSlugs, slug) {
		role := strings.TrimSpace(def.ReservedEscalationRole)
		if role == "" || strings.TrimSpace(actorUserID) == "" || !s.userHoldsRootRole(ctx, actorUserID, role) {
			return ErrGroupSlugReserved
		}
	}
	return nil
}

func slugReserved(reserved []string, slug string) bool {
	for _, r := range reserved {
		if strings.ToLower(strings.TrimSpace(r)) == slug {
			return true
		}
	}
	return false
}

// userHoldsRootRole reports whether the user holds the named LIVE configured
// role in the root group (the reserved-slug escalation check).
func (s *Service) userHoldsRootRole(ctx context.Context, userID, role string) bool {
	roles, _ := s.rootRoleSlugsByUser(ctx, userID)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// subjectMemberOfGroup reports whether the user holds a DIRECT role in the live
// group addressed by (persona, slug), and that group's id when they do.
func (s *Service) subjectMemberOfGroup(ctx context.Context, userID, persona, slug string) (string, bool, error) {
	groups, err := s.ListSubjectGroups(ctx, userID, SubjectKindUser)
	if err != nil {
		return "", false, err
	}
	for _, g := range groups {
		if g.Persona == persona && g.InstanceSlug == slug {
			return g.GroupID, true, nil
		}
	}
	return "", false, nil
}

// AssignRemoteApplicationRoleAs is the actor-aware remote-application role
// assignment behind PUT /<persona>/:instance_slug/remote-applications/:app/
// roles/:role (#263) — the SubjectKindRemoteApp symmetric of the member-role
// route. The :app slug must resolve to a remote application CONTROLLED BY the
// addressed group (same scope rule as the remote-app delete route), and the
// actor must hold the persona's credentials:manage capability plus every
// permission the role confers (no-escalation), so nobody can grant an
// application authority above their own.
func (s *Service) AssignRemoteApplicationRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, appSlug, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, ErrRoleNotAssignable)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	ra, err := s.GetRemoteApplicationBySlug(ctx, appSlug)
	if err != nil {
		return err
	}
	// Scope: the application must belong to the addressed group — a
	// credentials manager cannot attach another group's issuer.
	if strings.TrimSpace(ra.PermissionGroupID) != strings.TrimSpace(gid) {
		return ErrRemoteApplicationNotFound
	}
	if err := s.authorizeRoleGrant(ctx, st, sch, persona, gid, actorUserID, PermCredentialsManage(persona), role); err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, ra.ID, SubjectKindRemoteApp, role)
}
