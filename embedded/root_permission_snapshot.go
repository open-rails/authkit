package embedded

import (
	"context"
	"errors"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/rootsnapshot"
)

func (s *engine) rootPermissionSnapshot(ctx context.Context, userID string) (*rootsnapshot.Value, error) {
	if s.pg == nil {
		return nil, errors.New("root permission snapshot requires PostgreSQL")
	}
	store := s.groupStore()
	groupID, err := s.resolveGroupID(ctx, store, authkit.RootGroup())
	if err != nil {
		return nil, err
	}
	grants, err := store.GrantsOnGroup(ctx, s.groupSchemaOrDefault(), authkit.UserSubject(userID), groupID)
	if err != nil {
		return nil, err
	}
	return rootsnapshot.New(s.cfg.Token.Issuer, groupID, grants)
}
