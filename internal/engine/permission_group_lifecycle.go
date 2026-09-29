package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
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
func (s *Engine) requireDefinedGroupRole(_ context.Context, _ *permissionGroupStore, _ string, persona iam.Persona, role iam.Role) error {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); !ok {
		return fmt.Errorf("role %q is not a role of a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
	}
	return nil
}

// Group lifecycle: host operations. The host app owns the entity a group
// guards (a channel), so it decides who may make or remove one. host, when
// set, is the host's own transaction (withAuthorityMutationIn).

// CreateGroup creates a group of a declared persona. ng.Owner, when set, must
// be a live account; it is seeded with the owner role.
func (s *Engine) CreateGroup(ctx context.Context, ng iam.NewGroup, host pgx.Tx) (iam.Group, error) {
	persona := ng.Persona
	if _, ok := s.groupSchemaOrDefault().Persona(persona); !ok || persona == iam.RootPersona {
		return iam.Group{}, fmt.Errorf("unknown group persona %q: %w", persona, iam.ErrUnknownGroupPersona)
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
	err := s.withAuthorityMutationIn(ctx, iam.SystemActor(), host, func(st *permissionGroupStore) error {
		if owner != nil {
			if err := s.requireLiveOwner(ctx, st, *owner); err != nil {
				return err
			}
		}
		id, err := st.CreateGroup(ctx, persona)
		if err != nil {
			return err
		}
		if owner != nil {
			if err := s.requireMFAForRoleAssignment(ctx, st.q, id, persona, *owner, persona.OwnerRole()); err != nil {
				return err
			}
			if err := st.AssignRole(ctx, id, *owner, persona.OwnerRole()); err != nil {
				return err
			}
		}
		out, err = st.groupByID(ctx, id)
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
func (s *Engine) DeleteGroup(ctx context.Context, ref iam.GroupRef, host pgx.Tx) error {
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
		if persona == iam.RootPersona {
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
func (s *Engine) PurgeGroup(ctx context.Context, ref iam.GroupRef, host pgx.Tx) error {
	err := s.withAuthorityMutationIn(ctx, iam.SystemActor(), host, func(st *permissionGroupStore) error {
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
