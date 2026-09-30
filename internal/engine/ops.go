package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/rbac"
)

// hostTx resolves the options of an operation that takes only InTx: the
// host's transaction, nil when absent.
func hostTx(op string, opts []ops.Option) (pgx.Tx, error) {
	o, err := ops.Resolve(op, opts, ops.KindTx)
	return o.Tx, err
}

// noOptions refuses every option: op takes none yet.
func noOptions(op string, opts []ops.Option) error {
	_, err := ops.Resolve(op, opts)
	return err
}

// Persona resolves a persona name declared in Config.Roles (root always is).
func (s *Engine) Persona(name string) (iam.Persona, error) {
	p, ok := s.groupSchemaOrDefault().PersonaNamed(name)
	if !ok {
		return iam.Persona{}, fmt.Errorf("persona %q: %w", name, iam.ErrUnknownGroupPersona)
	}
	return p, nil
}

// Permission resolves a registered concrete permission.
func (s *Engine) Permission(text string) (iam.Perm, error) {
	p, ok := s.groupSchemaOrDefault().Permission(text)
	if !ok {
		return iam.Perm{}, fmt.Errorf("%w: %q", iam.ErrUnknownPermission, text)
	}
	return p, nil
}

// Role resolves role text `<persona>:<name>`: a declared role or a persona's
// owner role, else iam.ErrRoleNotAssignable (iam.ErrUnknownGroupPersona for
// an undeclared persona).
func (s *Engine) Role(text string) (iam.Role, error) {
	r := ident.RoleText(strings.TrimSpace(text))
	if r.IsZero() {
		return iam.Role{}, fmt.Errorf("role %q must be <persona>:<name>: %w", text, iam.ErrRoleNotAssignable)
	}
	if _, err := s.catalogRole(r); err != nil {
		return iam.Role{}, err
	}
	return r, nil
}

// RolePermissions returns role's grants in the catalog, includes flattened:
// permissions and patterns, in declaration order.
func (s *Engine) RolePermissions(role iam.Role) ([]iam.Perm, error) {
	def, err := s.catalogRole(role)
	if err != nil {
		return nil, err
	}
	out := make([]iam.Perm, len(def.Permissions))
	for i, p := range def.Permissions {
		out[i] = ident.Perm(p)
	}
	return out, nil
}

// catalogRole is role's compiled definition: a declared role or a persona's
// owner role, else iam.ErrRoleNotAssignable (iam.ErrUnknownGroupPersona for
// an undeclared persona).
func (s *Engine) catalogRole(role iam.Role) (rbac.Role, error) {
	if role.IsZero() {
		return rbac.Role{}, fmt.Errorf("the zero role: %w", iam.ErrRoleNotAssignable)
	}
	sch := s.groupSchemaOrDefault()
	if _, ok := sch.Persona(role.Persona()); !ok {
		return rbac.Role{}, fmt.Errorf("role %q: %w", role, iam.ErrUnknownGroupPersona)
	}
	def, ok := sch.Role(role.Persona(), role)
	if !ok {
		return rbac.Role{}, fmt.Errorf("%q is not a role of %q: %w", role, role.Persona(), iam.ErrRoleNotAssignable)
	}
	return def, nil
}

// userIn reads the account id through q: inside a transaction, it sees the
// transaction's own writes.
func userIn(ctx context.Context, q db.DBTX, id string) (iam.User, error) {
	r, err := db.New(q).UserByID(ctx, id)
	if err != nil {
		return iam.User{}, err
	}
	return publicUser(&r, time.Now()), nil
}
