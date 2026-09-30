package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
)

// lockPermissionGroup is the shared lifecycle lock. The caller supplies a
// transaction and takes this lock before role definitions, grants or invite
// rows; subsequent statements then observe the state after any waited writer.
func lockPermissionGroup(ctx context.Context, q db.DBTX, groupID string) error {
	_, err := db.New(q).PermissionGroupLiveForUpdate(ctx, groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	return err
}

// requireDefinedGroupRole: a durable reference names a catalog role.
func (s *Engine) requireDefinedGroupRole(persona iam.Persona, role iam.Role) error {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); !ok {
		return fmt.Errorf("role %q is not a role of a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
	}
	return nil
}

// Group lifecycle: host operations. The host app owns the entity a group
// guards (a channel), so it decides who may make or remove one. ops.InTx
// runs them in the host's own transaction (withAuthorityMutationIn).

// CreateGroup creates a group of a declared persona. ng.Owner, when set, must
// be a live account; it is seeded with the owner role. With ng.ID, creating
// an existing live group of the same persona returns it unchanged; a deleted
// group or another persona under that id is iam.ErrGroupConflict.
func (s *Engine) CreateGroup(ctx context.Context, ng iam.NewGroup, opts ...ops.Option) (iam.Group, error) {
	host, err := hostTx("CreateGroup", opts)
	if err != nil {
		return iam.Group{}, err
	}
	persona := ng.Persona
	if _, ok := s.groupSchemaOrDefault().Persona(persona); !ok || persona == iam.RootPersona() {
		return iam.Group{}, fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
	}
	id := strings.TrimSpace(ng.ID)
	if id != "" {
		var ok bool
		if id, ok = canonicalUUID(id); !ok {
			return iam.Group{}, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("id"))
		}
	}
	var owner *iam.Subject
	if ng.Owner != nil {
		o := iam.Subject{Kind: ng.Owner.Kind, ID: strings.TrimSpace(ng.Owner.ID)}
		if err := validSubject(o); err != nil {
			return iam.Group{}, err
		}
		o.ID, _ = canonicalUUID(o.ID)
		owner = &o
	}
	var out iam.Group
	err = s.withAuthorityMutationIn(ctx, iam.SystemActor(), host, func(st *permissionGroupStore) error {
		if id != "" {
			existing, err := db.New(st.q).AuthorityGroupState(ctx, id)
			switch {
			case err == nil && existing.DeletedAt == nil && existing.Persona == persona.String():
				out = publicGroup(existing)
				return nil
			case err == nil:
				return iam.ErrGroupConflict
			case !errors.Is(err, pgx.ErrNoRows):
				return err
			}
		}
		if owner != nil {
			if err := s.requireLiveOwner(ctx, st, *owner); err != nil {
				return err
			}
		}
		gid, err := st.CreateGroup(ctx, id, persona)
		if err != nil {
			return err
		}
		if owner != nil {
			if err := s.requireMFAForRoleAssignment(ctx, st.q, gid, persona, *owner, persona.OwnerRole()); err != nil {
				return err
			}
			if err := st.AssignRole(ctx, gid, *owner, persona.OwnerRole()); err != nil {
				return err
			}
		}
		out, err = st.groupByID(ctx, gid)
		return err
	})
	return out, err
}

// requireLiveOwner refuses a first owner that could not act: an unknown
// account, or a banned, deleted or reserved one.
func (s *Engine) requireLiveOwner(ctx context.Context, st *permissionGroupStore, owner iam.Subject) error {
	if owner.Kind == iam.SubjectKindUser {
		exists, err := db.New(st.q).UserExists(ctx, owner.ID)
		if err != nil {
			return err
		}
		if !exists {
			return iam.ErrUserNotFound
		}
	}
	live, err := subjectUsable(ctx, st.q, owner)
	if err == nil && !live {
		err = iam.ErrInsufficientAuthority
	}
	return err
}

// DeleteGroup soft-deletes a group: it stops resolving and granting, while
// its rows stay until PurgeGroup. Deleting a deleted group is a no-op; the
// root group cannot be deleted.
func (s *Engine) DeleteGroup(ctx context.Context, ref iam.GroupRef, opts ...ops.Option) error {
	host, err := hostTx("DeleteGroup", opts)
	if err != nil {
		return err
	}
	return s.withAuthorityMutationIn(ctx, iam.SystemActor(), host, func(st *permissionGroupStore) error {
		if ref.IsRoot() {
			return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
		}
		if !isUUID(ref.ID()) {
			return iam.ErrGroupNotFound
		}
		q := db.New(st.q)
		group, err := q.PermissionGroupForUpdate(ctx, ref.ID())
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrGroupNotFound
		}
		if err != nil || group.DeletedAt != nil {
			return err
		}
		persona := ident.Persona(group.Persona)
		if persona == iam.RootPersona() {
			return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
		}
		gid := strings.ToLower(ref.ID())
		surviving, err := outsideApplicationOwnerGroups(ctx, st, gid)
		if err != nil {
			return err
		}
		if err := q.PermissionGroupSoftDelete(ctx, db.PermissionGroupSoftDeleteParams{ID: gid, DeletedAt: st.now()}); err != nil {
			return err
		}
		if err := st.record(ctx, groupEvent(iam.EventGroupDeleted, gid, persona)); err != nil {
			return err
		}
		for _, id := range surviving {
			if err := s.requireRemainingOwner(ctx, st, id, iam.Subject{}); err != nil {
				return err
			}
		}
		return nil
	})
}

// PurgeGroup permanently deletes a group, live or soft-deleted, with every
// role, key and link in it. Purging an unknown group is a no-op.
func (s *Engine) PurgeGroup(ctx context.Context, ref iam.GroupRef, opts ...ops.Option) error {
	host, err := hostTx("PurgeGroup", opts)
	if err != nil {
		return err
	}
	err = s.withAuthorityMutationIn(ctx, iam.SystemActor(), host, func(st *permissionGroupStore) error {
		if ref.IsRoot() {
			return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
		}
		if !isUUID(ref.ID()) {
			return iam.ErrGroupNotFound
		}
		return s.deleteGroupTx(ctx, st, strings.ToLower(ref.ID()))
	})
	if errors.Is(err, iam.ErrGroupNotFound) {
		return nil
	}
	return err
}
