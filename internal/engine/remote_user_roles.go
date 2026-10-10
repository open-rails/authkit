package engine

// Federated grants: an email invitation in a group whose issuer a user's
// token is trusted by, accepted with that verified address, gives the
// issuer's user (its remote_users record) the invitation's role there. The
// user's tokens hold the role's permissions in the group, within their
// application's role as every trusted issuer's token.

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// remoteUserToken is a trusted issuer's user token with a verified email:
// what may see and accept the group's invitations.
type remoteUserToken struct {
	app            *iam.RemoteApplication
	subject, email string
	claims         verify.Claims
}

func remoteUserOf(v auth.Verified) (remoteUserToken, bool) {
	rv, ok := v.(resourceVerified)
	if !ok || rv.access.Application == nil || rv.access.Claims.Kind != verify.TokenUser {
		return remoteUserToken{}, false
	}
	cl := rv.access.Claims
	email := strings.ToLower(strings.TrimSpace(cl.Email))
	if !cl.EmailVerified || email == "" {
		return remoteUserToken{}, false
	}
	return remoteUserToken{app: rv.access.Application, subject: cl.Subject, email: email, claims: cl}, true
}

// RemoteInvitations are the email invitations with a role pending in the
// group v's issuer is trusted by, for v's verified email. A credential that
// is no trusted issuer's user with a verified email has none.
func (s *Engine) RemoteInvitations(ctx context.Context, v auth.Verified) ([]iam.Invitation, error) {
	u, ok := remoteUserOf(v)
	if !ok {
		return []iam.Invitation{}, nil
	}
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	rows, err := s.q.RemoteInvitationsPending(ctx, db.RemoteInvitationsPendingParams{PermissionGroupID: u.app.GroupID, Email: u.email})
	if err != nil {
		return nil, err
	}
	out := make([]iam.Invitation, 0, len(rows))
	for _, row := range rows {
		email, expires := row.Email, row.ExpiresAt
		inv := iam.Invitation{ID: row.ID, GroupID: row.PermissionGroupID, Email: &email, CreatedAt: row.CreatedAt, ExpiresAt: &expires}
		if row.Role != nil {
			inv.Role = ident.RoleText(*row.Role)
		}
		out = append(out, inv)
	}
	return out, nil
}

// AcceptRemoteInvitation redeems one of v's RemoteInvitations: v's user
// (recorded in the group's directory) holds its role in the group from now
// on, replacing any it held. iam.ErrInvitationNotFound for an id that is
// not one of them.
func (s *Engine) AcceptRemoteInvitation(ctx context.Context, v auth.Verified, id string) (iam.Role, error) {
	u, ok := remoteUserOf(v)
	id, valid := canonicalUUID(strings.TrimSpace(id))
	if !ok || !valid {
		return iam.Role{}, iam.ErrInvitationNotFound
	}
	if err := s.requirePG(); err != nil {
		return iam.Role{}, err
	}
	cl := u.claims
	if err := s.RecordRemoteUserClaims(ctx, u.app.GroupID, u.app.Issuer, u.subject, RemoteUserClaims{
		Email: u.email, EmailVerified: true, Name: cl.Name, Username: cl.Username, UpdatedAt: cl.UpdatedAt,
	}); err != nil {
		return iam.Role{}, err
	}
	user, err := s.RemoteUser(ctx, u.app.GroupID, u.app.Issuer, u.subject)
	if err != nil {
		return iam.Role{}, err
	}
	var role iam.Role
	err = s.withGroupMutation(ctx, iam.SystemIdentity(), iam.GroupByID(u.app.GroupID), func(st *permissionGroupStore, g groupTarget) error {
		q := db.New(st.q)
		text, err := q.RemoteInvitationConsume(ctx, db.RemoteInvitationConsumeParams{ID: id, PermissionGroupID: g.ID, Email: u.email})
		if errors.Is(err, pgx.ErrNoRows) || err == nil && text == nil {
			return iam.ErrInvitationNotFound
		}
		if err != nil {
			return err
		}
		role = ident.RoleText(*text)
		if err := s.requireDefinedGroupRole(ctx, st.q, g, role); err != nil {
			return err
		}
		return q.RemoteUserRoleUpsert(ctx, db.RemoteUserRoleUpsertParams{PermissionGroupID: g.ID, RemoteUserID: user.ID, Role: role.String(), InvitationID: &id})
	})
	return role, err
}

// RemoteUserRoles are the roles trusted issuers' users hold in the group
// ref, oldest first.
func (s *Engine) RemoteUserRoles(ctx context.Context, ref iam.GroupRef) ([]iam.RemoteUserRole, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	g, err := s.resolveGroup(ctx, s.groupStore(), ref)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.RemoteUserRolesByGroup(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	out := make([]iam.RemoteUserRole, 0, len(rows))
	for _, row := range rows {
		r := iam.RemoteUserRole{RemoteUserID: row.RemoteUserID, Issuer: row.Issuer, Subject: row.Subject, Role: ident.RoleText(row.Role), CreatedAt: row.CreatedAt}
		if row.Email != nil {
			r.Email = *row.Email
		}
		out = append(out, r)
	}
	return out, nil
}

// RemoveRemoteUserRole ends the role a trusted issuer's user holds in the
// group ref. who needs <persona>:members:manage there and coverage of the
// role; iam.ErrUserNotFound when the user holds none.
func (s *Engine) RemoveRemoteUserRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, remoteUserID string, opts ...ops.Option) error {
	host, err := hostTx("RemoveRemoteUserRole", opts)
	if err != nil {
		return err
	}
	if err := requireIdentity(who); err != nil {
		return err
	}
	if err := s.requirePG(); err != nil {
		return err
	}
	remoteUserID, ok := canonicalUUID(strings.TrimSpace(remoteUserID))
	if !ok {
		return iam.ErrUserNotFound
	}
	return s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		authority, err := s.identityAuthority(ctx, st, who, g)
		if err != nil {
			return err
		}
		if err := authority.requireCap(ident.MembersManage(g.Persona)); err != nil {
			return err
		}
		q := db.New(st.q)
		held, err := q.RemoteUserRoleByID(ctx, db.RemoteUserRoleByIDParams{PermissionGroupID: g.ID, RemoteUserID: remoteUserID})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrUserNotFound
		}
		if err != nil {
			return err
		}
		if err := s.requireHeldRoleCover(ctx, st, authority, g, ident.RoleText(held)); err != nil {
			return err
		}
		_, err = q.RemoteUserRoleDelete(ctx, db.RemoteUserRoleDeleteParams{PermissionGroupID: g.ID, RemoteUserID: remoteUserID})
		return err
	})
}

// remoteUserGrants are the grants of the role a trusted issuer's user holds
// in the group; none when it holds none.
func (s *Engine) remoteUserGrants(ctx context.Context, groupID, issuer, subject string) ([]string, error) {
	if s.pg == nil {
		return nil, nil
	}
	held, err := s.q.RemoteUserRoleBySubject(ctx, db.RemoteUserRoleBySubjectParams{PermissionGroupID: groupID, Issuer: issuer, Subject: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r, _ := s.groupSchemaOrDefault().AssignedRole(ident.Persona(held.Persona), ident.RoleText(held.Role), held.CustomPermissions)
	return r.Permissions, nil
}
