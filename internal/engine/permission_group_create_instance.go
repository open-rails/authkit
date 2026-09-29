package engine

// Group creation and identity updates. A user creates a group of a persona
// whose GroupCreation is enabled and becomes its owner; reserved slugs need
// `<persona>:*` held on root; the host's name-admission and creation hooks
// apply. An operator may create a group of any declared persona, with any
// owner or none, and skips those rules. Creating a slug the owner already
// belongs to returns that group with created=false, so seeding code can run
// on every boot.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
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
		return fmt.Errorf("%w: %w", errmodel.ErrGroupCreationRefused, err)
	}
	return nil
}

// CreateGroup creates a group and seeds its owner. Machine actors cannot
// create groups.
func (s *Engine) CreateGroup(ctx context.Context, a iam.Actor, ng iam.NewGroup) (iam.Group, bool, error) {
	if err := requireActor(a); err != nil {
		return iam.Group{}, false, err
	}
	if err := s.requirePG(); err != nil {
		return iam.Group{}, false, err
	}
	sch := s.groupSchemaOrDefault()
	ref := iam.GroupBySlug(ng.Persona, ng.Slug)
	if _, ok := sch.Persona(ref.Persona()); !ok || ref.IsRoot() {
		return iam.Group{}, false, fmt.Errorf("unknown group persona %q: %w", ref.Persona(), iam.ErrUnknownGroupPersona)
	}
	if err := iam.ValidateGroupInstanceSlug(ref); err != nil {
		return iam.Group{}, false, fmt.Errorf("%w: %w", iam.ErrGroupSlugInvalid, err)
	}
	displayName := strings.TrimSpace(ng.DisplayName)
	if len(displayName) > 256 {
		return iam.Group{}, false, iam.ErrGroupSlugInvalid
	}
	var owner *iam.Subject
	switch a.Kind() {
	case iam.ActorOperator:
		if ng.Owner != nil {
			o := iam.Subject{Kind: ng.Owner.Kind, ID: strings.TrimSpace(ng.Owner.ID)}
			if err := validSubject(o); err != nil {
				return iam.Group{}, false, err
			}
			owner = &o
		}
	case iam.ActorUser:
		self := iam.UserSubject(a.ID())
		if ng.Owner != nil && *ng.Owner != self {
			return iam.Group{}, false, iam.ErrInsufficientAuthority
		}
		if !sch.CreationEnabled(ref.Persona()) {
			return iam.Group{}, false, fmt.Errorf("group persona %q does not allow creation: %w", ref.Persona(), iam.ErrUnknownGroupPersona)
		}
		if err := s.userMayCreate(ctx, a, ref); err != nil {
			return iam.Group{}, false, err
		}
		owner = &self
	default:
		return iam.Group{}, false, iam.ErrInsufficientAuthority
	}

	var created iam.Group
	err := s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		id, err := st.CreateGroupNamed(ctx, ref, displayName)
		if err != nil {
			return err
		}
		if owner != nil {
			if err := s.requireMFAForRoleAssignment(ctx, st.q, id, ref.Persona(), *owner, iam.OwnerRole); err != nil {
				return err
			}
			if err := st.AssignRole(ctx, id, *owner, iam.OwnerRole); err != nil {
				return err
			}
		}
		created, err = st.groupByID(ctx, id)
		return err
	})
	if err == nil {
		return created, true, nil
	}
	if !isUniqueViolation(err, "permission_groups_persona_instance_uidx") && !errors.Is(err, iam.ErrGroupSlugTaken) {
		return iam.Group{}, false, err
	}
	// The slug is taken: a re-run by the owner returns the existing group.
	if owner != nil {
		st := s.groupStore()
		if id, lerr := st.GroupByLiveInstanceSlug(ctx, ref); lerr == nil {
			role, rerr := st.directRole(ctx, id, *owner)
			if rerr != nil {
				return iam.Group{}, false, rerr
			}
			if role != "" {
				g, gerr := st.groupByID(ctx, id)
				return g, false, gerr
			}
		}
	}
	return iam.Group{}, false, iam.ErrGroupSlugTaken
}

// userMayCreate applies a user's creation rules: the slug claim, then the
// host's name-admission and creation hooks.
func (s *Engine) userMayCreate(ctx context.Context, a iam.Actor, ref iam.GroupRef) error {
	if err := s.authorizeSlugClaim(ctx, s.groupStore(), a, ref); err != nil {
		return err
	}
	if err := s.admitName(ctx, iam.NameAdmissionRequest{OwnerKind: "group", Persona: ref.Persona(), ActorID: a.ID(), RequestedName: ref.Slug(), Operation: iam.NameCreate}); err != nil {
		return err
	}
	return s.mayCreateInstance(ctx, ref, a.ID())
}

// authorizeSlugClaim is the gate for an actor claiming a slug (creation and
// rename): the persona's SlugPattern, and reserved slugs, which only an actor
// holding `<persona>:*` on root may take. An operator skips it.
func (s *Engine) authorizeSlugClaim(ctx context.Context, st *permissionGroupStore, a iam.Actor, ref iam.GroupRef) error {
	if a.Kind() == iam.ActorOperator {
		return nil
	}
	sch := s.groupSchemaOrDefault()
	persona, slug := ref.Persona(), ref.Slug()
	if !sch.CreationSlugAllowed(persona, slug) {
		return fmt.Errorf("resource slug %q does not match the %q creation slug pattern: %w", slug, persona, iam.ErrGroupSlugInvalid)
	}
	if !sch.SlugReserved(persona, slug) {
		return nil
	}
	rootID, err := s.rootGroup(ctx, st)
	if err != nil {
		return err
	}
	auth, err := s.actorAuthority(ctx, st, a, groupTarget{ID: rootID, Persona: iam.RootPersona})
	if errors.Is(err, iam.ErrInsufficientAuthority) || err == nil && !auth.covers(persona.OwnerGrant()) {
		return iam.ErrGroupSlugReserved
	}
	return err
}

// UpdateGroup renames a group or changes its display name. It needs
// <persona>:self:update; a new slug also passes the slug claim, and a user's
// rename the host's name admission. The root group has no identity to update.
func (s *Engine) UpdateGroup(ctx context.Context, a iam.Actor, ref iam.GroupRef, u iam.GroupUpdate) (iam.Group, error) {
	var out iam.Group
	if err := requireActor(a); err != nil {
		return out, err
	}
	if u.DisplayName != nil && len(strings.TrimSpace(*u.DisplayName)) > 256 {
		return out, iam.ErrGroupSlugInvalid
	}
	err := s.withGroupMutation(ctx, ref, func(st *permissionGroupStore, g groupTarget) error {
		auth, err := s.actorAuthority(ctx, st, a, g)
		if err != nil {
			return err
		}
		if g.Persona == iam.RootPersona {
			return fmt.Errorf("the root group has no slug or display name: %w", iam.ErrUnknownGroupPersona)
		}
		if err := auth.requireCap(iam.PermSelfUpdate(g.Persona)); err != nil {
			return err
		}
		if u.Slug != nil {
			if err := s.renameGroup(ctx, st, a, g, *u.Slug); err != nil {
				return err
			}
		}
		if u.DisplayName != nil {
			if err := st.SetGroupDisplayName(ctx, g.ID, strings.TrimSpace(*u.DisplayName)); err != nil {
				return err
			}
		}
		out, err = st.groupByID(ctx, g.ID)
		return err
	})
	return out, err
}

func (s *Engine) renameGroup(ctx context.Context, st *permissionGroupStore, a iam.Actor, g groupTarget, slug string) error {
	next := iam.GroupBySlug(g.Persona, slug)
	if next.Slug() == g.Slug {
		return nil
	}
	if err := iam.ValidateGroupInstanceSlug(next); err != nil {
		return fmt.Errorf("%w: %w", iam.ErrGroupSlugInvalid, err)
	}
	if err := s.authorizeSlugClaim(ctx, st, a, next); err != nil {
		return err
	}
	var managed bool
	if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote_applications WHERE permission_group_id=$1::uuid AND trust_root='domain')`, g.ID).Scan(&managed); err != nil {
		return err
	}
	if managed {
		return iam.ErrGroupSlugApplicationManaged
	}
	if a.Kind() != iam.ActorOperator {
		if err := s.admitName(ctx, iam.NameAdmissionRequest{OwnerKind: "group", Persona: g.Persona, OwnerID: g.ID, ActorID: a.ID(), CurrentName: g.Slug, RequestedName: next.Slug(), Operation: iam.NameRename}); err != nil {
			return err
		}
	}
	return st.renameGroupSlug(ctx, g.ID, next.Slug(), s.NamingPolicy())
}
