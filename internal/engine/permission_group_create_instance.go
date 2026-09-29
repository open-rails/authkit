package engine

// Generated persona-instance CREATION (#263): the core policy behind
// POST /<persona>. Per-persona config (GroupCreation) declares the slug
// pattern and the reserved-slug list; the host cost gate is
// the mayCreateInstance admission seam (WithInstanceAdmission); velocity limits
// (per-IP + per-user) are enforced by the HTTP layer. Creation is idempotent
// for existing members: re-creating a slug you already belong to returns the
// group instead of a conflict (bootstrap re-runs).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/rbac"
)

// mayCreateInstance consults the host admission seam (#263). A nil predicate
// allows; a predicate error is wrapped as ErrGroupCreationRefused. The seam
// sees the normalized slug (#269) so a host can refuse a specific namespace
// outright, not merely price the attempt.
func (s *Engine) mayCreateInstance(ctx context.Context, group iam.GroupRef, subject string) error {
	if s.instanceAdmission == nil {
		return nil
	}
	if err := s.instanceAdmission(ctx, group, subject); err != nil {
		return fmt.Errorf("%w: %w", iam.ErrGroupCreationRefused, err)
	}
	return nil
}

// CreateInstanceForSubject is the #263 creation path: validate the slug against
// the persona's creation config, gate reserved slugs on `<persona>:*` held on
// root, consult the host admission seam, then create the group with ownerUserID
// seeded as owner. If the slug is already held and the caller is a member of
// that group, it returns Created=false instead of a conflict.
func (s *Engine) CreateInstanceForSubject(ctx context.Context, group iam.GroupRef, displayName, ownerUserID string) (authflow.CreateInstanceResult, error) {
	var out authflow.CreateInstanceResult
	if err := s.requirePG(); err != nil {
		return out, err
	}
	sch := s.groupSchemaOrDefault()
	persona, slug := group.Persona(), group.Slug()
	ownerUserID = strings.TrimSpace(ownerUserID)
	out.InstanceSlug = slug

	if !sch.CreationEnabled(persona) {
		return out, fmt.Errorf("group persona %q does not allow generated instance creation: %w", persona, iam.ErrUnknownGroupPersona)
	}
	if ownerUserID == "" {
		return out, iam.ErrInsufficientRoleAuthority
	}
	if err := s.authorizeSlugClaim(ctx, sch, group, ownerUserID); err != nil {
		return out, err
	}

	if err := s.admitName(ctx, iam.NameAdmissionRequest{OwnerKind: "group", Persona: persona, ActorID: ownerUserID, RequestedName: slug, Operation: iam.NameCreate}); err != nil {
		return out, err
	}

	// Host cost gate (anti-squat split: velocity is authkit's, cost is the host's).
	if err := s.mayCreateInstance(ctx, group, ownerUserID); err != nil {
		return out, err
	}

	gid, err := s.CreatePermissionGroup(ctx, iam.CreatePermissionGroupRequest{
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
	if isUniqueViolation(err, "permission_groups_persona_instance_uidx") || errors.Is(err, iam.ErrGroupSlugTaken) {
		existing, member, merr := s.subjectMemberOfGroup(ctx, ownerUserID, group)
		if merr != nil {
			return out, merr
		}
		if member {
			out.GroupID = existing
			return out, nil // Created=false
		}
		return out, iam.ErrGroupSlugTaken
	}
	return out, err
}

// authorizeSlugClaim is the single gate for a user claiming an instance slug
// (creation and rename, #263/#292): the built-in slug rule, the persona's
// SlugPattern, and reserved slugs, which only a holder of `<persona>:*` on root
// may take.
func (s *Engine) authorizeSlugClaim(ctx context.Context, sch *rbac.Schema, group iam.GroupRef, actorUserID string) error {
	persona, slug := group.Persona(), group.Slug()
	if err := iam.ValidateGroupInstanceSlug(group); err != nil {
		return fmt.Errorf("%w: %w", iam.ErrGroupSlugInvalid, err)
	}
	if !sch.CreationSlugAllowed(persona, slug) {
		return fmt.Errorf("resource slug %q does not match the %q creation slug pattern: %w", slug, persona, iam.ErrGroupSlugInvalid)
	}
	if !sch.SlugReserved(persona, slug) {
		return nil
	}
	actorUserID = strings.TrimSpace(actorUserID)
	if actorUserID == "" {
		return iam.ErrGroupSlugReserved
	}
	st := s.groupStore()
	rootID, err := st.RootGroupID(ctx)
	if err != nil {
		return err
	}
	ok, err := st.CanOnGroup(ctx, sch, iam.UserSubject(actorUserID), rootID, persona.OwnerGrant())
	if err != nil {
		return err
	}
	if !ok {
		return iam.ErrGroupSlugReserved
	}
	return nil
}

// subjectMemberOfGroup reports whether the user holds a DIRECT role in the live
// group addressed by (persona, slug), and that group's id when they do.
func (s *Engine) subjectMemberOfGroup(ctx context.Context, userID string, group iam.GroupRef) (string, bool, error) {
	groups, err := s.ListSubjectGroups(ctx, iam.UserSubject(userID))
	if err != nil {
		return "", false, err
	}
	for _, g := range groups {
		if g.Persona == group.Persona() && g.InstanceSlug == group.Slug() {
			return g.GroupID, true, nil
		}
	}
	return "", false, nil
}
