package authcore

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

func (s *Service) authorizeAccountAuthority(ctx context.Context, actorUserID, targetUserID string) error {
	actorUserID = strings.TrimSpace(actorUserID)
	targetUserID = strings.TrimSpace(targetUserID)
	if actorUserID == "" || targetUserID == "" {
		return ErrInsufficientRoleAuthority
	}
	if actorUserID == targetUserID || s.pg == nil {
		return nil
	}
	st := s.groupStore()
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
func (s *Service) SoftDeleteUserAs(ctx context.Context, actorUserID, userID string) error {
	if err := s.authorizeAccountAuthority(ctx, actorUserID, userID); err != nil {
		return err
	}
	return s.SoftDeleteUser(ctx, userID)
}

// HardDeleteUserAs is the actor-aware HardDeleteUser.
func (s *Service) HardDeleteUserAs(ctx context.Context, actorUserID, userID string) error {
	if err := s.authorizeAccountAuthority(ctx, actorUserID, userID); err != nil {
		return err
	}
	return s.HardDeleteUser(ctx, userID)
}

// AdminRevokeUserSessionsAs is the actor-aware AdminRevokeUserSessions.
func (s *Service) AdminRevokeUserSessionsAs(ctx context.Context, actorUserID, userID string) error {
	if err := s.authorizeAccountAuthority(ctx, actorUserID, userID); err != nil {
		return err
	}
	return s.AdminRevokeUserSessions(ctx, userID)
}
