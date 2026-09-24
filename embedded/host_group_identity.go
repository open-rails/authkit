package embedded

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// GroupInstanceByID reads the identity already resolved by a host. It never
// interprets the UUID as a mutable name.
func (s *engine) GroupInstanceByID(ctx context.Context, groupID string) (GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return GroupInstance{}, err
	}
	return s.groupStore().GroupInstanceByID(ctx, strings.TrimSpace(groupID))
}

// GroupInstancesByIDs is the listing form of GroupInstanceByID: one query.
func (s *engine) GroupInstancesByIDs(ctx context.Context, groupIDs []string) (map[string]GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	ids, err := groupBatch(groupIDs)
	if err != nil {
		return nil, err
	}
	return s.groupStore().GroupInstancesByIDs(ctx, ids)
}

// EffectivePermissionsForGroups resolves one subject's grant patterns on many
// exact groups in one query; a rename cannot redirect any of them.
func (s *engine) EffectivePermissionsForGroups(ctx context.Context, subject authkit.Subject, groupIDs []string) (map[string][]authkit.Perm, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	ids, err := groupBatch(groupIDs)
	if err != nil {
		return nil, err
	}
	grants, err := s.groupStore().GrantsOnGroups(ctx, s.groupSchemaOrDefault(), subject, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]authkit.Perm, len(grants))
	for gid, patterns := range grants {
		perms := make([]authkit.Perm, len(patterns))
		for i, p := range patterns {
			perms[i] = authkit.Perm(p)
		}
		out[gid] = perms
	}
	return out, nil
}

func groupBatch(groupIDs []string) ([]string, error) {
	ids := make([]string, 0, len(groupIDs))
	seen := make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > authkit.MaxGroupBatch {
		return nil, fmt.Errorf("group batch has %d ids; at most %d", len(ids), authkit.MaxGroupBatch)
	}
	return ids, nil
}

// CanOnGroup evaluates live assignments for the exact resolved group. A rename
// or reclaimed name cannot redirect this check to a different owner.
func (s *engine) CanOnGroup(ctx context.Context, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	return s.groupStore().CanOnGroup(ctx, s.groupSchemaOrDefault(), subject, strings.TrimSpace(groupID), perm)
}

// DeleteGroupInstanceByID is the trusted host's lifecycle primitive. The host
// authorizes deletion before calling it; retries always target the captured UUID.
// The entire descendant subtree is deleted. ReleaseSlug applies to every
// deleted canonical name, preserving earlier alias reservations.
func (s *engine) DeleteGroupInstanceByID(ctx context.Context, groupID string, opts DeletePermissionGroupOptions) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := NewPermissionGroupStore(tx)
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return err
	}
	if err := s.deleteGroupTx(ctx, st, strings.TrimSpace(groupID), opts); err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return nil
		}
		return err
	}
	return tx.Commit(ctx)
}

// SoftDeleteGroupInstanceByID retains the entire subtree while making it
// inactive. Group retirement and account deletion share the authority lock.
func (s *engine) SoftDeleteGroupInstanceByID(ctx context.Context, groupID string) (authkit.GroupInstance, error) {
	var out authkit.GroupInstance
	groupID = strings.TrimSpace(groupID)
	err := s.withAuthorityMutation(ctx, func(st *PermissionGroupStore) error {
		ids, err := st.lockGroupSubtree(ctx, groupID)
		if err != nil {
			return err
		}
		surviving, err := outsideSubtreeApplicationOwnerGroups(ctx, st, groupID)
		if err != nil {
			return err
		}
		if _, err = st.q.Exec(ctx, `UPDATE permission_groups SET deleted_at=COALESCE(deleted_at,$2),updated_at=CASE WHEN deleted_at IS NULL THEN $2 ELSE updated_at END WHERE id=ANY($1::uuid[])`, ids, st.now()); err != nil {
			return err
		}
		for _, id := range surviving {
			if err := s.requireRemainingOwner(ctx, st, id, authkit.Subject{}); err != nil {
				return err
			}
		}
		out, err = st.GroupInstanceByID(ctx, groupID)
		return err
	})
	return out, err
}
