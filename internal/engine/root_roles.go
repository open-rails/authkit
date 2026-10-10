package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
)

// rootRoles returns the root role of each account among ids that holds one.
// A stored role no longer defined confers nothing and is absent.
func (s *Engine) rootRoles(ctx context.Context, ids []string) (map[string]iam.Role, error) {
	out := make(map[string]iam.Role, len(ids))
	ids = uuidsOnly(ids)
	if len(ids) == 0 || s.pg == nil {
		return out, nil
	}
	st := s.groupStore()
	gid, err := s.rootGroup(ctx, st)
	if err != nil {
		return nil, err
	}
	rows, err := db.New(st.q).GroupUserRolesForUsers(ctx, db.GroupUserRolesForUsersParams{GroupID: gid, UserIds: ids})
	if err != nil {
		return nil, err
	}
	sch := s.groupSchemaOrDefault()
	for _, r := range rows {
		role := ident.RoleText(r.Role)
		if _, ok := sch.AssignedRole(iam.RootPersona(), role, r.CustomPermissions); ok {
			out[r.UserID] = role
		}
	}
	return out, nil
}
