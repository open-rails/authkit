package engine

// Invite links (#134/#147): a high-entropy, unbound, single-use code for a
// group role. A signed-in user who redeems it gets the role; possession of the
// link is the credential. The code is returned once; only its sha256 is
// stored. Minting needs invited self-registration (externalInvitesEnabled): a
// stranger can join only if they can obtain an account. Issuance follows rule
// CRED (credential_issuers.go).

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/secret"
)

const (
	defaultGroupInviteTTL = 72 * time.Hour
	// maxGroupInviteTTL caps a link's lifetime (#247): a longer request is
	// clamped, never rejected, bounding a leaked or forgotten link.
	maxGroupInviteTTL = 30 * 24 * time.Hour
)

// externalInvitesEnabled reports whether invite LINKS may be minted. They make
// sense only when AuthKit permits invited self-registration: open (anyone may
// sign up) or invite_only (sign up ONLY via an invite). Under closed an invited
// stranger has no way to obtain an account, so the capability is OFF (an admin
// assigns roles directly via the members endpoint instead).
func (s *Engine) externalInvitesEnabled() bool {
	mode := s.cfg.Registration.NativeUserMode
	return mode == iam.RegistrationModeOpen || mode == iam.RegistrationModeInviteOnly
}

// inviteURL builds the host-facing accept-invite link: BaseURL + the configured
// Frontend.InvitePath + #code=. The fragment never reaches a server; the SPA
// reads the code and POSTs it to redeem.
func (s *Engine) inviteURL(code string) string {
	q := url.Values{}
	q.Set("code", code)
	return s.authkitURL(s.cfg.Frontend.InvitePath, q)
}

// requireIssuableRole refuses a role that is not in the group's catalog.
func (s *Engine) requireIssuableRole(g groupTarget, role iam.Role) ([]string, error) {
	if err := s.requireDefinedGroupRole(g.Persona, role); err != nil {
		return nil, err
	}
	return s.roleGrants(g.Persona, role)
}

// RedeemInvitation redeems code for the signed-in user a: a link must be
// live (not revoked, expired or used) and its issuer live, and the redeemer
// live. The role is assigned in the same transaction and the link consumed.
// Idempotent: a redeemer already holding the role succeeds without using it.
// code may also be a role-carrying account invitation (an add by email): only
// the account that has verified the invited address accepts it.
func (s *Engine) RedeemInvitation(ctx context.Context, a iam.Actor, code string) (authflow.InviteRedemption, error) {
	var out authflow.InviteRedemption
	code = strings.TrimSpace(code)
	if a.Kind() != iam.ActorUser || !isUUID(a.ID()) {
		return out, iam.ErrInsufficientAuthority
	}
	if code == "" {
		return out, errmodel.ErrInvalidInvite
	}
	redeemer := iam.UserSubject(a.ID())
	codeHash := secret.Hash(code)
	err := s.withAuthorityMutation(ctx, a, func(st *permissionGroupStore) error {
		q := db.New(st.q)
		groupID, err := q.InviteLinkGroupByCode(ctx, codeHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.acceptAccountInvite(ctx, st, redeemer, codeHash, &out)
		}
		if err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
			return err
		}
		link, err := q.InviteLinkByCodeForUpdate(ctx, db.InviteLinkByCodeForUpdateParams{CodeHash: codeHash, GroupID: groupID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInvitationNotFound
		}
		if err != nil {
			return err
		}
		out.GroupID, out.Persona = link.GroupID, ident.Persona(link.Persona)
		out.Role = ident.RoleText(link.Role)
		if link.RevokedAt != nil || !link.IssuerLive {
			return errmodel.ErrInvitationRevoked
		}
		if link.ExpiresAt != nil && !link.ExpiresAt.After(time.Now().UTC()) {
			return errmodel.ErrInvitationExpired
		}
		live, err := subjectUsable(ctx, st.q, redeemer)
		if err != nil {
			return err
		}
		if !live {
			return iam.ErrInsufficientAuthority
		}
		already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
		if err != nil || already {
			return err
		}
		if link.RedeemedAt != nil {
			return iam.ErrInvitationNotFound
		}
		if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
			return err
		}
		return q.InviteLinkRedeem(ctx, link.ID)
	})
	if err != nil {
		return authflow.InviteRedemption{}, err
	}
	return out, nil
}

// acceptAccountInvite accepts a role-carrying account invitation for an
// existing account: the redeemer's verified email must be the invited address,
// so the role lands only with the consent of whoever proved it. Anything else
// is ErrInvitationNotFound, never a hint about the invitation.
func (s *Engine) acceptAccountInvite(ctx context.Context, st *permissionGroupStore, redeemer iam.Subject, codeHash string, out *authflow.InviteRedemption) error {
	q := db.New(st.q)
	groupID, err := q.AccountInviteGroupByCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	if err := lockPermissionGroup(ctx, st.q, groupID); err != nil {
		return err
	}
	invite, err := q.AccountInviteByCodeForUpdate(ctx, db.AccountInviteByCodeForUpdateParams{CodeHash: codeHash, GroupID: groupID, UserID: redeemer.ID})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !invite.Addressed {
		return iam.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	out.GroupID, out.Persona = invite.GroupID, ident.Persona(invite.Persona)
	out.Role = ident.RoleText(invite.Role)
	if invite.RevokedAt != nil || !invite.IssuerLive {
		return errmodel.ErrInvitationRevoked
	}
	if !invite.ExpiresAt.After(time.Now().UTC()) {
		return errmodel.ErrInvitationExpired
	}
	live, err := subjectUsable(ctx, st.q, redeemer)
	if err != nil {
		return err
	}
	if !live {
		return iam.ErrInsufficientAuthority
	}
	already, err := subjectHasRole(ctx, st.q, groupID, redeemer.ID, out.Role)
	if err != nil || already {
		return err
	}
	if invite.ConsumedAt != nil {
		return iam.ErrInvitationNotFound
	}
	if err := s.assignInvitedRole(ctx, st, groupID, out.Persona, redeemer.ID, out.Role); err != nil {
		return err
	}
	return q.AccountInviteConsume(ctx, db.AccountInviteConsumeParams{ID: invite.ID, UserID: redeemer.ID})
}

// subjectHasRole reports whether the user already holds role in the group.
func subjectHasRole(ctx context.Context, q db.DBTX, groupID, userID string, role iam.Role) (bool, error) {
	return db.New(q).GroupUserHasRole(ctx, db.GroupUserHasRoleParams{GroupID: groupID, UserID: userID, Role: role.String()})
}
