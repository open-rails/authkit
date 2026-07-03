package authcore

import (
	"context"
	"errors"
	"fmt"
	authkit "github.com/open-rails/authkit"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// ErrNotGroupMember is returned when a remote_application holds no role in its
// controlling permission-group.
var ErrNotGroupMember = authkit.ErrNotGroupMember

// remoteApplicationGroupID resolves a remote_application's controlling
// permission_group_id (its REQUIRED group, #111). appID is the remote_application
// uuid. Returns ErrInvalidRemoteApplication on empty input and
// ErrRemoteApplicationNotFound when no such app exists.
func (s *Service) remoteApplicationGroupID(ctx context.Context, appID string) (string, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return "", ErrInvalidRemoteApplication
	}
	q := db.ForSchema(s.pg, s.dbSchema())
	var gid string
	err := q.QueryRow(ctx,
		`SELECT permission_group_id::text FROM profiles.remote_applications WHERE id = $1::uuid`,
		appID).Scan(&gid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrRemoteApplicationNotFound
	}
	if err != nil {
		return "", err
	}
	return gid, nil
}

// AddRemoteApplicationMember grants a remote_application a role in its own
// controlling permission-group.
func (s *Service) AddRemoteApplicationMember(ctx context.Context, appID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return err
	}
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return fmt.Errorf("role is required")
	}
	var persona string
	q := db.ForSchema(s.pg, s.dbSchema())
	if err := q.QueryRow(ctx, `SELECT persona FROM profiles.permission_groups WHERE id = $1::uuid`, gid).Scan(&persona); err != nil {
		return err
	}
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group", role, persona)
	}
	return s.groupStore().AssignRole(ctx, gid, strings.TrimSpace(appID), SubjectKindRemoteApp, role)
}

// remoteApplicationRoles returns the roles a remote_application holds in its
// controlling permission-group, or ErrNotGroupMember when it holds none.
// Unexported: not on the public contract; only authcore tests use it.
func (s *Service) remoteApplicationRoles(ctx context.Context, appID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return nil, err
	}
	asg, err := s.groupStore().WalkAssignments(ctx, gid, strings.TrimSpace(appID), SubjectKindRemoteApp)
	if err != nil {
		return nil, err
	}
	var roles []string
	for _, a := range asg {
		roles = append(roles, a.Roles...)
	}
	if len(roles) == 0 {
		return nil, ErrNotGroupMember
	}
	return roles, nil
}

// ResolveRemoteApplicationAuthority resolves a remote_application's effective
// permissions: the additive walk-up of every role it holds across its
// controlling permission-group's parent chain (#111). Returns an empty slice
// (no error) when the app holds no roles.
func (s *Service) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	gid, err := s.remoteApplicationGroupID(ctx, appID)
	if err != nil {
		return nil, err
	}
	st := s.groupStore()
	asg, err := st.WalkAssignments(ctx, gid, strings.TrimSpace(appID), SubjectKindRemoteApp)
	if err != nil {
		return nil, err
	}
	if len(asg) == 0 {
		return []string{}, nil
	}
	ids := make([]string, 0, len(asg))
	for _, a := range asg {
		ids = append(ids, a.PermissionGroupID)
	}
	resolver, err := st.CustomRolesFor(ctx, ids)
	if err != nil {
		return nil, err
	}
	perms := s.groupSchemaOrDefault().ResolveGrants(asg, resolver)
	if perms == nil {
		perms = []string{}
	}
	return perms, nil
}
