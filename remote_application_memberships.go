package authkit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/iam"

	"github.com/jackc/pgx/v5"
)

// remoteApplicationGroupID resolves a remote_application's controlling
// permission_group_id (its REQUIRED group, #111). appID is the remote_application
// uuid. Returns ErrInvalidRemoteApplication on empty input and
// ErrRemoteApplicationNotFound when no such app exists.
func (s *engine) remoteApplicationGroupID(ctx context.Context, appID string) (string, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return "", iam.ErrInvalidRemoteApplication
	}
	q := s.pg
	var gid string
	err := q.QueryRow(ctx,
		`SELECT permission_group_id::text FROM remote_applications WHERE id = $1::uuid`,
		appID).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return "", err
	}
	return gid, nil
}

// AssignRemoteApplicationRole grants a remote_application a role in its own
// controlling permission-group with NO actor check (#308): reachable only via
// bootstrap and authkit.engine.Genesis(). engine callers use
// AssignRemoteApplicationRoleAs.
func (s *engine) AssignRemoteApplicationRole(ctx context.Context, appID string, role iam.Role) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return err
	}
	role = iam.Role(strings.ToLower(strings.TrimSpace(string(role))))
	if role == "" {
		return fmt.Errorf("role is required")
	}
	var persona iam.Persona
	q := s.pg
	if err := q.QueryRow(ctx, `SELECT persona FROM permission_groups WHERE id = $1::uuid`, gid).Scan(&persona); err != nil {
		return err
	}
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
	}
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		if err := s.requireDefinedGroupRole(ctx, st, gid, persona, role); err != nil {
			return err
		}
		subject := iam.RemoteAppSubject(strings.TrimSpace(appID))
		old, err := st.directRole(ctx, gid, subject)
		if err != nil {
			return err
		}
		if old != role {
			if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
				return err
			}
		}
		return st.AssignRole(ctx, gid, iam.RemoteAppSubject(strings.TrimSpace(appID)), role)
	})
}

// remoteApplicationRoles returns the roles a remote_application holds in its
// controlling permission-group, or ErrNotGroupMember when it holds none.
// Unexported: not on the public contract; only authcore tests use it.
func (s *engine) remoteApplicationRoles(ctx context.Context, appID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return nil, err
	}
	asg, err := s.groupStore().WalkAssignments(ctx, gid, iam.RemoteAppSubject(strings.TrimSpace(appID)))
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, a := range asg {
		if a.Role != "" {
			roles = append(roles, string(a.Role))
		}
	}
	if len(roles) == 0 {
		return nil, iam.ErrNotGroupMember
	}
	return roles, nil
}

// ResolveRemoteApplicationAuthority resolves a remote_application's effective
// permissions — the additive walk-up of every role it holds across its
// controlling permission-group's parent chain (#111) — plus the owning group
// instance the authority is bound to (#248). Permissions is an empty slice
// (no error) when the app holds no roles.
func (s *engine) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (iam.RemoteApplicationAuthority, error) {
	var out iam.RemoteApplicationAuthority
	if err := s.requirePG(); err != nil {
		return out, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return out, iam.ErrInvalidRemoteApplication
	}
	q := s.pg
	var gid string
	err := q.QueryRow(ctx,
		`SELECT ra.permission_group_id::text, pg.persona, COALESCE(pg.instance_slug, '')
		 FROM remote_applications ra
		 JOIN permission_groups pg ON pg.id = ra.permission_group_id
		 WHERE ra.id = $1::uuid AND ra.enabled AND pg.deleted_at IS NULL`,
		appID).Scan(&gid, &out.Persona, &out.InstanceSlug)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.RemoteApplicationAuthority{}, iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return iam.RemoteApplicationAuthority{}, err
	}
	out.PermissionGroupID = gid
	out.AuthorityIssuer = s.cfg.Token.Issuer
	out.Permissions, err = s.groupStore().GrantsOnGroup(ctx, s.groupSchemaOrDefault(), iam.RemoteAppSubject(appID), gid)
	if err != nil {
		return iam.RemoteApplicationAuthority{}, err
	}
	return out, nil
}
