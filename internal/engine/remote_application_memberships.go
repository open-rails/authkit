package engine

import (
	"context"
	"errors"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"

	"github.com/jackc/pgx/v5"
)

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
		`SELECT ra.permission_group_id::text, pg.persona
		 FROM remote_applications ra
		 JOIN permission_groups pg ON pg.id = ra.permission_group_id
		 WHERE ra.id = $1::uuid AND ra.enabled AND pg.deleted_at IS NULL AND `+registrarLive("ra"),
		appID).Scan(&gid, scanPersona(&out.Persona))
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.RemoteApplicationAuthority{}, iam.ErrRemoteApplicationNotFound
	}
	if err != nil {
		return iam.RemoteApplicationAuthority{}, err
	}
	out.PermissionGroupID = gid
	out.AuthorityIssuer = s.cfg.Token.Issuer
	grants, err := s.groupStore().GrantsOnGroup(ctx, s.groupSchemaOrDefault(), iam.RemoteApplicationSubject(appID), gid)
	if err != nil {
		return iam.RemoteApplicationAuthority{}, err
	}
	// An application can present no second factor (see withoutMFAGrants).
	if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(grants) {
		grants = []string{}
	}
	out.Permissions = ident.Perms(grants)
	return out, nil
}
