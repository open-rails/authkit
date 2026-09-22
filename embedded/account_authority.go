package embedded

// Account-authority guard (#286): #136 no-escalation extended from role grants
// to the account surface. An actor may ban, delete, or revoke the sessions of a
// target only if the actor's effective root grants cover the target's, so a
// bounded root:users:* operator can never lock out or seize a more privileged
// account (the root owner). Runtime callers (HTTP admin routes, hosts acting
// for a signed-in operator) use the actor-aware methods; system paths (purge
// worker, self-delete) keep the unchecked ones.

import (
	"context"
	"errors"
	"strings"

	authkit "github.com/open-rails/authkit"
)

func (s *engine) authorizeAccountAuthorityOn(ctx context.Context, st *PermissionGroupStore, actorUserID, targetUserID string) error {
	actorUserID = strings.TrimSpace(actorUserID)
	targetUserID = strings.TrimSpace(targetUserID)
	if actorUserID == "" || targetUserID == "" {
		return ErrInsufficientRoleAuthority
	}
	if s.pg == nil {
		return nil
	}
	present, err := authorizationActorPresent(ctx, st.q, actorUserID)
	if err != nil {
		return err
	}
	if !present {
		return ErrInsufficientRoleAuthority
	}
	if actorUserID == targetUserID {
		return nil
	}
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return nil // no root group ⇒ nobody holds root authority
		}
		return err
	}
	sch := s.groupSchemaOrDefault()
	targetGrants, err := st.GrantsOnGroup(ctx, sch, authkit.UserSubject(targetUserID), gid)
	if err != nil {
		return err
	}
	if len(targetGrants) == 0 {
		return nil
	}
	actorGrants, err := st.GrantsOnGroup(ctx, sch, authkit.UserSubject(actorUserID), gid)
	if err != nil {
		return err
	}
	if !grantsCoverAll(actorGrants, targetGrants) {
		return ErrAccountAuthorityEscalation
	}
	return nil
}

// SoftDeleteUserAs is the actor-aware SoftDeleteUser.
func (s *engine) SoftDeleteUserAs(ctx context.Context, actorUserID, userID string) error {
	if strings.TrimSpace(actorUserID) == "" {
		return ErrInsufficientRoleAuthority
	}
	return s.softDeleteUser(ctx, actorUserID, userID)
}

// AdminRevokeAccountSessionsAs is the actor-aware AdminRevokeAccountSessions.
func (s *engine) AdminRevokeAccountSessionsAs(ctx context.Context, actorUserID, userID string) (authkit.AccountSessionRevocation, error) {
	if strings.TrimSpace(actorUserID) == "" {
		return authkit.AccountSessionRevocation{}, ErrInsufficientRoleAuthority
	}
	return s.revokeAccountSessions(ctx, actorUserID, userID)
}
