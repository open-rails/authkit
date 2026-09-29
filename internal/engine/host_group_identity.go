package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// GroupInstanceByID reads the identity already resolved by a host. It never
// interprets the UUID as a mutable name.
func (s *Engine) GroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	if err := s.requirePG(); err != nil {
		return iam.GroupInstance{}, err
	}
	return s.groupStore().GroupInstanceByID(ctx, strings.TrimSpace(groupID))
}

// GroupInstancesByIDs is the listing form of GroupInstanceByID: one query.
func (s *Engine) GroupInstancesByIDs(ctx context.Context, groupIDs []string) (map[string]iam.GroupInstance, error) {
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
func (s *Engine) EffectivePermissionsForGroups(ctx context.Context, subject iam.Subject, groupIDs []string) (map[string][]iam.Perm, error) {
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
	out := make(map[string][]iam.Perm, len(grants))
	for gid, patterns := range grants {
		perms := make([]iam.Perm, len(patterns))
		for i, p := range patterns {
			perms[i] = iam.Perm(p)
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
	if len(ids) > iam.MaxBatch {
		return nil, fmt.Errorf("group batch has %d ids; at most %d", len(ids), iam.MaxBatch)
	}
	return ids, nil
}

// CanOnGroup evaluates live assignments for the exact resolved group. A rename
// or reclaimed name cannot redirect this check to a different owner. An
// unregistered perm is ErrUnknownPermission.
func (s *Engine) CanOnGroup(ctx context.Context, subject iam.Subject, groupID string, perm iam.Perm) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	sch := s.groupSchemaOrDefault()
	if !sch.KnownPermission(perm) {
		return false, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, perm)
	}
	return s.groupStore().CanOnGroup(ctx, sch, subject, strings.TrimSpace(groupID), perm)
}

// DeleteGroupInstanceByID is the trusted host's lifecycle primitive. The host
// authorizes deletion before calling it; retries always target the captured UUID.
// ReleaseSlug applies to the deleted canonical name, preserving earlier alias
// reservations.
func (s *Engine) DeleteGroupInstanceByID(ctx context.Context, groupID string, opts iam.DeletePermissionGroupOptions) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	st := newPermissionGroupStore(tx)
	if err := s.lockAuthority(ctx, st.q); err != nil {
		return err
	}
	if err := s.deleteGroupTx(ctx, st, strings.TrimSpace(groupID), opts); err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			return nil
		}
		return err
	}
	return tx.Commit(ctx)
}

// SoftDeleteGroupInstanceByID retains the group while making it inactive.
// Group retirement and account deletion share the authority lock.
func (s *Engine) SoftDeleteGroupInstanceByID(ctx context.Context, groupID string) (iam.GroupInstance, error) {
	var out iam.GroupInstance
	groupID = strings.TrimSpace(groupID)
	err := s.withAuthorityMutation(ctx, func(st *permissionGroupStore) error {
		if err := st.lockGroup(ctx, groupID); err != nil {
			return err
		}
		surviving, err := outsideApplicationOwnerGroups(ctx, st, groupID)
		if err != nil {
			return err
		}
		if _, err = st.q.Exec(ctx, `UPDATE permission_groups SET deleted_at=COALESCE(deleted_at,$2),updated_at=CASE WHEN deleted_at IS NULL THEN $2 ELSE updated_at END WHERE id=$1::uuid`, groupID, st.now()); err != nil {
			return err
		}
		for _, id := range surviving {
			if err := s.requireRemainingOwner(ctx, st, id, iam.Subject{}); err != nil {
				return err
			}
		}
		out, err = st.GroupInstanceByID(ctx, groupID)
		return err
	})
	return out, err
}
