package engine

import (
	"context"
	"errors"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// A registration-only invite creates an account in the selected directory;
// it assigns no group role. Global account inviters prove their capability on
// root separately, where credential pins and captured ceilings still apply.
func (s *Engine) requireAccountInvitation(ctx context.Context, st *permissionGroupStore, who auth.Identity, g groupTarget) error {
	authority, err := s.identityAuthority(ctx, st, who, g)
	if err != nil {
		return err
	}
	err = authority.requireCap(ident.Perm(g.Persona.String() + ":users:invite"))
	if err == nil || g.Persona != iam.TenantPersona() || !errors.Is(err, iam.ErrInsufficientAuthority) {
		return err
	}
	root, err := s.resolveGroup(ctx, st, iam.RootGroup())
	if err != nil {
		return err
	}
	authority, err = s.identityAuthority(ctx, st, who, root)
	if err != nil {
		return err
	}
	return authority.requireCap(ident.RootUsersInvite)
}
