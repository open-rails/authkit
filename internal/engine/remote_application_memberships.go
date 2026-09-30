package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
)

// storedApplicationAuthority is the verifier's view of an enabled application's
// stored authority: the controlling group it is bound to (#248)
// and its effective permissions there, the union of its roles on that group
// and on root (#111). No permissions is an empty slice, not an error.
func (s *Engine) storedApplicationAuthority(ctx context.Context, appID string) (verify.PermissionScope, []iam.Perm, error) {
	if err := s.requirePG(); err != nil {
		return verify.PermissionScope{}, nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return verify.PermissionScope{}, nil, iam.ErrInvalidRemoteApplication
	}
	row, err := s.q.RemoteApplicationAuthority(ctx, appID)
	if errors.Is(err, pgx.ErrNoRows) {
		return verify.PermissionScope{}, nil, iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return verify.PermissionScope{}, nil, err
	}
	scope := verify.PermissionScope{GroupID: row.PermissionGroupID, AuthorityIssuer: s.cfg.Token.Issuer, Persona: ident.Persona(row.Persona)}
	grants, err := s.groupStore().GrantsOnGroup(ctx, s.groupSchemaOrDefault(), iam.RemoteApplicationSubject(appID), scope.GroupID)
	if err != nil {
		return verify.PermissionScope{}, nil, err
	}
	// An application can present no second factor (see withoutMFAGrants).
	if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(grants) {
		grants = []string{}
	}
	return scope, ident.Perms(grants), nil
}
