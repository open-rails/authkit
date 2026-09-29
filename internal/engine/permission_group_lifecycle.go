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
)

// lockPermissionGroup is the shared lifecycle lock. The caller supplies a
// transaction and takes this lock before role definitions, grants or invite
// rows; subsequent statements then observe the state after any waited writer.
func lockPermissionGroup(ctx context.Context, q db.DBTX, groupID string) error {
	var id string
	err := q.QueryRow(ctx, `SELECT id::text FROM permission_groups WHERE id=$1::uuid AND deleted_at IS NULL FOR UPDATE`, groupID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrGroupNotFound
	}
	return err
}

// A role must exist when a durable reference is created. Catalog definitions
// are immutable configuration; custom definitions are read under the group lock.
func (s *Engine) requireDefinedGroupRole(ctx context.Context, st *permissionGroupStore, groupID string, persona iam.Persona, role iam.Role) error {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return nil
	}
	resolver, err := st.CustomRolesFor(ctx, []string{groupID})
	if err != nil {
		return err
	}
	if _, ok := resolver(groupID, role); !ok {
		return errmodel.ErrUnknownRole
	}
	return nil
}

// Group lifecycle: host operations. The host app owns the entity a group
// guards (a channel), so it decides who may make or remove one. host, when
// set, is the host's own transaction (withAuthorityMutationIn).

// CreateGroup creates a group of a declared persona. ng.Owner, when set, must
// be a live account; it is seeded with the owner role.
func (s *Engine) CreateGroup(ctx context.Context, ng iam.NewGroup, host pgx.Tx) (iam.Group, error) {
	persona := iam.Persona(strings.TrimSpace(string(ng.Persona)))
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
			if err := s.requireMFAForRoleAssignment(ctx, st.q, id, persona, *owner, iam.OwnerRole); err != nil {
				return err
			}
			if err := st.AssignRole(ctx, id, *owner, iam.OwnerRole); err != nil {
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
		var exists bool
		if err := st.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid)`, owner.ID).Scan(&exists); err != nil {
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
		var persona iam.Persona
		var deleted bool
		err := st.q.QueryRow(ctx, `SELECT persona, deleted_at IS NOT NULL FROM permission_groups WHERE id=$1::uuid FOR UPDATE`, ref.ID()).Scan(&persona, &deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrGroupNotFound
		}
		if err != nil || deleted {
			return err
		}
		if persona == iam.RootPersona {
			return fmt.Errorf("the root group cannot be deleted: %w", iam.ErrUnknownGroupPersona)
		}
		gid := strings.ToLower(ref.ID())
		surviving, err := outsideApplicationOwnerGroups(ctx, st, gid)
		if err != nil {
			return err
		}
		if _, err := st.q.Exec(ctx, `UPDATE permission_groups SET deleted_at=$2 WHERE id=$1::uuid`, gid, st.now()); err != nil {
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
// role, custom role, key and link in it. Purging an unknown group is a no-op.
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
