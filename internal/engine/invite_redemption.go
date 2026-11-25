package engine

// One redemption for every invitation and every kind of role holder: a
// native account (invite links, account invitations) or a trusted issuer's
// user (remote invitations). The checks live here once.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
)

// invitationsOn refuses every redemption while Invitations.Disabled.
func (s *Engine) invitationsOn() error {
	if !config.InvitationsOn(s.cfg) {
		return iam.ErrInvitationsDisabled
	}
	return nil
}

// invitation is an invitation locked for redemption. table is its
// credential table (group_invite_links or account_registration_invites).
type invitation struct {
	table                     string
	id                        string
	group                     groupTarget
	role                      iam.Role // zero: a plain email invitation
	used, revoked, issuerLive bool
	expiresAt                 *time.Time
}

// roleHolder is who an invitation's role lands with.
type roleHolder interface {
	live(ctx context.Context, st *permissionGroupStore) (bool, error)
	// held is the role the holder has in g; zero for none.
	held(ctx context.Context, st *permissionGroupStore, g groupTarget) (iam.Role, error)
	// refuseOwnerLoss refuses replacing the holder's role when it is the
	// last owner of g that counts.
	refuseOwnerLoss(ctx context.Context, st *permissionGroupStore, g groupTarget) error
	// noMFA names the holder when it cannot enroll a second factor here.
	noMFA() string
	// assign gives the holder role in g, replacing any it held.
	assign(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role, invitationID string) error
}

// redeemInvitation gives h inv's role and uses inv up. inv must be live (not
// revoked, expired or used) and its inviter live, still holding authority
// over it in this application's catalog; h must be live. A holder already
// holding the role succeeds without using inv.
func (s *Engine) redeemInvitation(ctx context.Context, st *permissionGroupStore, inv invitation, h roleHolder) error {
	if inv.revoked || !inv.issuerLive {
		return errmodel.ErrInvitationRevoked
	}
	if err := s.requireCredentialUse(ctx, st, inv.table, inv.id, inv.group.ID, errmodel.ErrInvitationRevoked); err != nil {
		return err
	}
	if inv.expiresAt != nil && !inv.expiresAt.After(time.Now().UTC()) {
		return errmodel.ErrInvitationExpired
	}
	live, err := h.live(ctx, st)
	if err != nil {
		return err
	}
	if !live {
		return iam.ErrInsufficientAuthority
	}
	if !inv.role.IsZero() {
		old, err := h.held(ctx, st, inv.group)
		if err != nil || old == inv.role {
			return err
		}
		if inv.used {
			return iam.ErrInvitationNotFound
		}
		if err := s.landInvitedRole(ctx, st, inv.group, h, old, inv.role, inv.id); err != nil {
			return err
		}
	} else if inv.used {
		return iam.ErrInvitationNotFound
	}
	q := db.New(st.q)
	if inv.table == "group_invite_links" {
		return q.InviteLinkRedeem(ctx, inv.id)
	}
	return q.AccountInviteConsume(ctx, inv.id)
}

// landInvitedRole replaces h's role old in g with role. It may keep or raise
// h's grants, never strip one (ErrRoleAssignmentEscalation), nor take a
// group's last owner; role must be defined, and one that requires MFA lands
// only with a holder that can enroll it.
func (s *Engine) landInvitedRole(ctx context.Context, st *permissionGroupStore, g groupTarget, h roleHolder, old, role iam.Role, invitationID string) error {
	if !old.IsZero() && old != role {
		oldGrants, err := s.roleGrants(ctx, st.q, g, old)
		if err != nil {
			return err
		}
		offered, err := s.roleGrants(ctx, st.q, g, role)
		if err != nil {
			return err
		}
		if !grantsCoverAll(offered, oldGrants) {
			return iam.ErrRoleAssignmentEscalation
		}
		if err := h.refuseOwnerLoss(ctx, st, g); err != nil {
			return err
		}
	}
	if err := s.requireDefinedGroupRole(ctx, st.q, g, role); err != nil {
		return err
	}
	if err := s.requireMFAHolder(ctx, st.q, g, role, h.noMFA()); err != nil {
		return err
	}
	return h.assign(ctx, st, g, role, invitationID)
}

// nativeHolder is a native account.
type nativeHolder struct {
	s  *Engine
	id string
}

func (h nativeHolder) subject() iam.Subject { return iam.UserSubject(h.id) }

func (h nativeHolder) live(ctx context.Context, st *permissionGroupStore) (bool, error) {
	return subjectUsable(ctx, st.q, h.subject())
}

func (h nativeHolder) held(ctx context.Context, st *permissionGroupStore, g groupTarget) (iam.Role, error) {
	return st.directRole(ctx, g, h.subject())
}

func (h nativeHolder) refuseOwnerLoss(ctx context.Context, st *permissionGroupStore, g groupTarget) error {
	return h.s.refuseOwnerLoss(ctx, st, g.ID, h.subject())
}

func (nativeHolder) noMFA() string { return "" }

func (h nativeHolder) assign(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role, _ string) error {
	return st.AssignRole(ctx, g.ID, h.subject(), role)
}

// remoteHolder is a trusted issuer's user: its record in the group's
// directory. It never counts as an owner and cannot enroll MFA here.
type remoteHolder struct {
	id     string
	active bool
}

func (h remoteHolder) live(context.Context, *permissionGroupStore) (bool, error) {
	return h.active, nil
}

func (h remoteHolder) held(ctx context.Context, st *permissionGroupStore, g groupTarget) (iam.Role, error) {
	role, err := db.New(st.q).RemoteUserRoleByID(ctx, db.RemoteUserRoleByIDParams{PermissionGroupID: g.ID, RemoteUserID: h.id})
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Role{}, nil
	}
	if err != nil {
		return iam.Role{}, err
	}
	return ident.RoleText(role), nil
}

func (remoteHolder) refuseOwnerLoss(context.Context, *permissionGroupStore, groupTarget) error {
	return nil
}

func (remoteHolder) noMFA() string { return "another issuer's user" }

func (h remoteHolder) assign(ctx context.Context, st *permissionGroupStore, g groupTarget, role iam.Role, invitationID string) error {
	return db.New(st.q).RemoteUserRoleUpsert(ctx, db.RemoteUserRoleUpsertParams{PermissionGroupID: g.ID, RemoteUserID: h.id, Role: role.String(), InvitationID: &invitationID})
}
