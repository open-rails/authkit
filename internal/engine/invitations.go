package engine

// Invitations: one resource over two stores. An invite link
// (group_invite_links) is a single-use code for a group role that a
// signed-in account redeems. An email invitation
// (account_registration_invites) lets the invited address register, granting
// its role, if any, on registration; an account that has verified the
// address may redeem it instead. Issuance follows rule CRED
// (credential_issuers.go): the creator is recorded, and the invitation dies
// with the creator's authority.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/secret"
)

// CreateInvitation creates an invite link (n.Email empty), or emails an
// invitation to n.Email. A link, and an email invitation carrying a role, need
// CAP(<p>:members:manage) plus COVER(role) in ref; a plain email invitation
// (no role) is issued in the root group and needs CAP(root:users:invite).
// Only a user or the system issues credentials. The code is returned once.
// ops.InTx applies to links only: an email is sent at once.
func (s *Engine) CreateInvitation(ctx context.Context, a iam.Actor, ref iam.GroupRef, n iam.NewInvitation, opts ...ops.Option) (iam.InvitationCreated, error) {
	host, err := hostTx("CreateInvitation", opts)
	if err != nil {
		return iam.InvitationCreated{}, err
	}
	creator, err := credentialIssuer(a)
	if err != nil {
		return iam.InvitationCreated{}, err
	}
	now := time.Now().UTC()
	if n.ExpiresAt != nil && !n.ExpiresAt.After(now) {
		return iam.InvitationCreated{}, errmodel.ErrInvalidExpiry
	}
	if strings.TrimSpace(n.Email) == "" {
		return s.createInviteLink(ctx, a, host, ref, n, creator, now)
	}
	if host != nil {
		return iam.InvitationCreated{}, errors.New("authkit: CreateInvitation takes InTx only for a link: an email invitation is sent at once")
	}
	return s.createEmailInvitation(ctx, a, ref, n, creator, now)
}

func (s *Engine) createInviteLink(ctx context.Context, a iam.Actor, host pgx.Tx, ref iam.GroupRef, n iam.NewInvitation, creator string, now time.Time) (iam.InvitationCreated, error) {
	if !s.externalInvitesEnabled() {
		return iam.InvitationCreated{}, iam.ErrExternalInvitesDisabled
	}
	if n.Role.IsZero() {
		return iam.InvitationCreated{}, errmodel.ErrInvalidInvite
	}
	expiresAt := now.Add(defaultGroupInviteTTL)
	if n.ExpiresAt != nil {
		expiresAt = n.ExpiresAt.UTC()
	}
	if limit := now.Add(maxGroupInviteTTL); expiresAt.After(limit) {
		expiresAt = limit
	}
	out := iam.InvitationCreated{Code: secret.Token(32)}
	err := s.withGroupMutationIn(ctx, a, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if _, err := s.requireIssuableRole(g, n.Role); err != nil {
			return err
		}
		if err := s.requireRoleGrant(ctx, st, a, g, ident.MembersManage(g.Persona), n.Role); err != nil {
			return err
		}
		row, err := db.New(st.q).InviteLinkInsert(ctx, db.InviteLinkInsertParams{
			GroupID: g.ID, Role: n.Role.String(), InvitedBy: nullable(creator), CodeHash: secret.Hash(out.Code), ExpiresAt: expiresAt,
			CatalogIssuer: s.cfg.Token.Issuer,
		})
		out.Invitation = iam.Invitation{ID: row.ID, GroupID: g.ID, Role: n.Role, CreatedBy: nullable(creator), CreatedAt: row.CreatedAt, ExpiresAt: &expiresAt}
		return err
	})
	if err != nil {
		return iam.InvitationCreated{}, err
	}
	out.URL = s.inviteURL(out.Code)
	return out, nil
}

func (s *Engine) createEmailInvitation(ctx context.Context, a iam.Actor, ref iam.GroupRef, n iam.NewInvitation, creator string, now time.Time) (iam.InvitationCreated, error) {
	email := contact.NormalizeEmail(n.Email)
	if err := contact.ValidateEmail(email); err != nil {
		return iam.InvitationCreated{}, err
	}
	role := n.Role
	if !role.IsZero() && !s.externalInvitesEnabled() {
		return iam.InvitationCreated{}, iam.ErrExternalInvitesDisabled
	}
	expiresAt := now.Add(defaultAccountRegistrationInviteTTL)
	if n.ExpiresAt != nil {
		expiresAt = n.ExpiresAt.UTC()
	}
	out := iam.InvitationCreated{Code: secret.Token(32)}
	err := s.withGroupMutation(ctx, a, ref, func(st *permissionGroupStore, g groupTarget) error {
		var groupID, roleText *string
		if role.IsZero() {
			if g.Persona != iam.RootPersona {
				return errmodel.ErrInvalidInvite
			}
			auth, err := s.actorAuthority(ctx, st, a, g)
			if err != nil {
				return err
			}
			if err := auth.requireCap(ident.RootUsersInvite); err != nil {
				return err
			}
		} else {
			if _, err := s.requireIssuableRole(g, role); err != nil {
				return err
			}
			if err := s.requireRoleGrant(ctx, st, a, g, ident.MembersManage(g.Persona), role); err != nil {
				return err
			}
			text := role.String()
			groupID, roleText = &g.ID, &text
		}
		row, err := db.New(st.q).AccountInviteInsert(ctx, db.AccountInviteInsertParams{
			Email: email, InvitedBy: nullable(creator), CodeHash: secret.Hash(out.Code), ExpiresAt: expiresAt, GroupID: groupID, Role: roleText,
			CatalogIssuer: s.cfg.Token.Issuer,
		})
		out.Invitation = iam.Invitation{ID: row.ID, GroupID: g.ID, Role: role, Email: nullable(email), CreatedBy: nullable(creator), CreatedAt: row.CreatedAt, ExpiresAt: &expiresAt}
		return err
	})
	if err != nil {
		return iam.InvitationCreated{}, err
	}
	out.URL = s.accountRegistrationInviteURL(out.Code)
	s.sendAccountRegistrationInviteEmail(ctx, email, out.URL)
	return out, nil
}

// ListInvitations lists the group's invitations, links and email
// invitations, newest first, active or not; never a code. Root's include the
// plain email invitations.
func (s *Engine) ListInvitations(ctx context.Context, ref iam.GroupRef, p iam.PageRequest) (iam.ListPage[iam.Invitation], error) {
	if err := s.requirePG(); err != nil {
		return iam.ListPage[iam.Invitation]{}, err
	}
	after, err := idCursor(p)
	if err != nil {
		return iam.ListPage[iam.Invitation]{}, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return iam.ListPage[iam.Invitation]{}, err
	}
	rows, err := db.New(st.q).InvitationsByGroup(ctx, db.InvitationsByGroupParams{
		GroupID: g.ID, Root: g.Persona == iam.RootPersona, After: after, PageLimit: int64(p.PageLimit() + 1),
	})
	if err != nil {
		return iam.ListPage[iam.Invitation]{}, err
	}
	items := make([]iam.Invitation, len(rows))
	for i, r := range rows {
		items[i] = iam.Invitation{
			ID: r.ID, GroupID: g.ID, Role: ident.RoleText(r.Role), Email: nullable(r.Email), CreatedBy: nullable(r.CreatedBy),
			CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RedeemedAt: r.RedeemedAt, RevokedAt: r.RevokedAt,
		}
	}
	return idPage(items, p.PageLimit(), func(i iam.Invitation) string { return i.ID }), nil
}

// RevokeInvitation revokes the group's invitation id. It needs the authority
// to issue it: CAP(<p>:members:manage) plus COVER of its role, or
// CAP(root:users:invite) for a plain email invitation. A revoked or redeemed
// invitation is a no-op; an id unknown in the group is
// iam.ErrInvitationNotFound.
func (s *Engine) RevokeInvitation(ctx context.Context, a iam.Actor, ref iam.GroupRef, id string, opts ...ops.Option) error {
	host, err := hostTx("RevokeInvitation", opts)
	if err != nil {
		return err
	}
	if err := requireActor(a); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	return s.withGroupMutationIn(ctx, a, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if !isUUID(id) {
			return iam.ErrInvitationNotFound
		}
		q := db.New(st.q)
		link, err := q.InviteLinkForRevoke(ctx, db.InviteLinkForRevokeParams{ID: id, GroupID: g.ID})
		switch {
		case err == nil:
			if link.RevokedAt != nil || link.RedeemedAt != nil {
				return nil
			}
			if err := s.requireCredentialRevoke(ctx, st, a, g, ident.MembersManage(g.Persona), ident.RoleText(link.Role)); err != nil {
				return err
			}
			return q.InviteLinkRetire(ctx, id)
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		invite, err := q.AccountInviteForRevoke(ctx, db.AccountInviteForRevokeParams{ID: id, GroupID: g.ID, Root: g.Persona == iam.RootPersona})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrInvitationNotFound
		}
		if err != nil || invite.RevokedAt != nil || invite.ConsumedAt != nil {
			return err
		}
		if invite.Role == "" {
			auth, err := s.actorAuthority(ctx, st, a, g)
			if err != nil {
				return err
			}
			if err := auth.requireCap(ident.RootUsersInvite); err != nil {
				return err
			}
		} else if err := s.requireCredentialRevoke(ctx, st, a, g, ident.MembersManage(g.Persona), ident.RoleText(invite.Role)); err != nil {
			return err
		}
		return q.AccountInviteRetire(ctx, id)
	})
}
