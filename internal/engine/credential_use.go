package engine

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
)

// credentialUseStands checks current authority, not the last cleanup run. A
// peer may be offline indefinitely without keeping a demoted creator's
// credential usable. This application judges only its own catalog.
func (s *Engine) credentialUseStands(ctx context.Context, st *permissionGroupStore, kind, id, group string) (bool, error) {
	if !isUUID(id) {
		return false, nil
	}
	c, err := db.New(st.q).CredentialAuthority(ctx, db.CredentialAuthorityParams{Kind: kind, ID: id, GroupID: group, Issuer: s.cfg.Token.Issuer})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.credentialStands(ctx, st, sweptCredential{table: kind, id: id, creator: c.Creator,
		group: groupTargetOf(db.PermissionGroup{ID: c.GroupID, Persona: c.Persona, TenantID: c.TenantID}), role: ident.RoleText(c.Role), needsCreator: c.NeedsCreator})
}

func (s *Engine) requireCredentialUse(ctx context.Context, st *permissionGroupStore, kind, id, group string, refusal error) error {
	ok, err := s.credentialUseStands(ctx, st, kind, id, group)
	if err != nil {
		return err
	}
	if !ok {
		return refusal
	}
	return nil
}
