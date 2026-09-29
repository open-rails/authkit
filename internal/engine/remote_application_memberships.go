package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/open-rails/authkit/iam"

	"github.com/jackc/pgx/v5"
)

// remoteApplicationGroupID resolves a remote_application's controlling
// permission_group_id (its REQUIRED group, #111). appID is the remote_application
// uuid. Returns ErrInvalidRemoteApplication on empty input and
// ErrRemoteApplicationNotFound when no such app exists.
func (s *Engine) remoteApplicationGroupID(ctx context.Context, appID string) (string, error) {
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

// remoteApplicationRoles returns the roles a remote_application holds in its
// controlling permission-group, or ErrNotGroupMember when it holds none.
// Unexported: not on the public contract; only authcore tests use it.
func (s *Engine) remoteApplicationRoles(ctx context.Context, appID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return nil, err
	}
	asg, err := s.groupStore().WalkAssignments(ctx, gid, iam.RemoteApplicationSubject(strings.TrimSpace(appID)))
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
// permissions — the union of its roles on its controlling permission-group and
// on root (#111) — plus the owning group
// instance the authority is bound to (#248). Permissions is an empty slice
// (no error) when the app holds no roles.
func (s *Engine) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (iam.RemoteApplicationAuthority, error) {
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
	out.Permissions, err = s.groupStore().GrantsOnGroup(ctx, s.groupSchemaOrDefault(), iam.RemoteApplicationSubject(appID), gid)
	if err != nil {
		return iam.RemoteApplicationAuthority{}, err
	}
	return out, nil
}
