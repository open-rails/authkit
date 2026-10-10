package engine

// Custom roles (#448): roles a group of a persona with CustomRoles defines at
// run time, held only in that group, `<persona>:custom-<name>`. A check reads
// the definition joined into the assignment it resolves, so an edit applies
// at the next request. Defining or changing one is granting: CAP
// <p>:roles:manage plus COVER of every grant before and after, and, when the
// role is held, the capabilities that hand it to its holders. Deleting one
// first takes it from every holder.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/helpers/auth"
)

// groupRole is role as group g holds it: a role g's persona declares, or a
// custom role g defines. ok is false for neither.
func (s *Engine) groupRole(ctx context.Context, q db.DBTX, g groupTarget, role iam.Role) (rbac.Role, bool, error) {
	sch := s.groupSchemaOrDefault()
	if !rbac.IsCustom(role) {
		r, ok := sch.Role(g.Persona, role)
		return r, ok, nil
	}
	if p, ok := sch.Persona(g.Persona); !ok || !p.CustomRoles || role.Persona() != g.Persona || !isUUID(g.ID) {
		return rbac.Role{}, false, nil
	}
	row, err := db.New(q).CustomRoleByName(ctx, db.CustomRoleByNameParams{GroupID: g.ID, Role: role.String()})
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.Role{}, false, nil
	}
	if err != nil {
		return rbac.Role{}, false, err
	}
	r, ok := sch.AssignedRole(g.Persona, role, row.Permissions)
	return r, ok, nil
}

// roleGrants returns what role confers in g, else ErrRoleNotAssignable.
func (s *Engine) roleGrants(ctx context.Context, q db.DBTX, g groupTarget, role iam.Role) ([]string, error) {
	r, ok, err := s.groupRole(ctx, q, g, role)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("role %q is not assignable in a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
	}
	return r.Permissions, nil
}

// requireDefinedGroupRole: a durable reference names a role g holds.
func (s *Engine) requireDefinedGroupRole(ctx context.Context, q db.DBTX, g groupTarget, role iam.Role) error {
	_, ok, err := s.groupRole(ctx, q, g, role)
	if err == nil && !ok {
		err = fmt.Errorf("%q is not a role of a %q group: %w", role, g.Persona, iam.ErrRoleNotAssignable)
	}
	return err
}

// roleRequiresMFA reports whether role, as g holds it, reaches a permission
// that needs MFA (Persona.RequireMFA).
func (s *Engine) roleRequiresMFA(ctx context.Context, q db.DBTX, g groupTarget, role iam.Role) (bool, error) {
	r, ok, err := s.groupRole(ctx, q, g, role)
	return ok && r.RequiresMFA, err
}

// declaredRole reports whether role is one persona declares (or its owner).
func (s *Engine) declaredRole(persona iam.Persona, role iam.Role) bool {
	_, ok := s.groupSchemaOrDefault().Role(persona, role)
	return ok
}

// groupRoleOut is r as a group lists it.
func (s *Engine) groupRoleOut(persona iam.Persona, r rbac.Role, row *db.CustomRoleByNameRow) iam.GroupRole {
	grants := ident.Perms(r.Permissions)
	out := iam.GroupRole{Name: r.Name, Grants: grants, Permissions: s.expandGrants(persona, grants), Custom: rbac.IsCustom(r.Name),
		RequiresMFA: r.RequiresMFA && s.TwoFactorEnabled()}
	if row != nil {
		out.CreatedAt, out.UpdatedAt = &row.CreatedAt, &row.UpdatedAt
	}
	return out
}

// expandGrants lists the catalog permissions grants cover in groups of
// persona: its own catalog, and on root every persona's.
func (s *Engine) expandGrants(persona iam.Persona, grants []iam.Perm) []iam.Perm {
	sch := s.groupSchemaOrDefault()
	names := []iam.Persona{persona}
	if persona == iam.RootPersona() {
		names = sch.Personas()
	}
	out := []iam.Perm{}
	for _, name := range names {
		p, _ := sch.Persona(name)
		out = append(out, rbac.Expand(p.Permissions, grants)...)
	}
	return out
}

// ListGroupRoles returns the roles assignable in the group: those its persona
// declares, then the custom roles it defines, by name.
func (s *Engine) ListGroupRoles(ctx context.Context, ref iam.GroupRef) ([]iam.GroupRole, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return nil, err
	}
	sch := s.groupSchemaOrDefault()
	p, _ := sch.Persona(g.Persona)
	out := make([]iam.GroupRole, 0, len(p.Roles))
	for _, r := range p.Roles {
		out = append(out, s.groupRoleOut(g.Persona, r, nil))
	}
	if !p.CustomRoles {
		return out, nil
	}
	rows, err := db.New(st.q).CustomRolesByGroup(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if r, ok := sch.AssignedRole(g.Persona, ident.RoleText(row.Role), row.Permissions); ok {
			out = append(out, s.groupRoleOut(g.Persona, r, (*db.CustomRoleByNameRow)(&row)))
		}
	}
	return out, nil
}

// GroupRole returns one role assignable in the group, iam.ErrRoleNotFound
// for any other.
func (s *Engine) GroupRole(ctx context.Context, ref iam.GroupRef, role iam.Role) (iam.GroupRole, error) {
	if err := s.requirePG(); err != nil {
		return iam.GroupRole{}, err
	}
	st := s.groupStore()
	g, err := s.resolveGroup(ctx, st, ref)
	if err != nil {
		return iam.GroupRole{}, err
	}
	if !rbac.IsCustom(role) {
		if r, ok := s.groupSchemaOrDefault().Role(g.Persona, role); ok {
			return s.groupRoleOut(g.Persona, r, nil), nil
		}
		return iam.GroupRole{}, iam.ErrRoleNotFound
	}
	r, row, err := s.customRole(ctx, st.q, g, role)
	if err != nil {
		return iam.GroupRole{}, err
	}
	return s.groupRoleOut(g.Persona, r, &row), nil
}

// customRole is the custom role g defines, iam.ErrRoleNotFound when it
// defines none by that name.
func (s *Engine) customRole(ctx context.Context, q db.DBTX, g groupTarget, role iam.Role) (rbac.Role, db.CustomRoleByNameRow, error) {
	p, ok := s.groupSchemaOrDefault().Persona(g.Persona)
	if !ok || !p.CustomRoles || !rbac.IsCustom(role) || role.Persona() != g.Persona {
		return rbac.Role{}, db.CustomRoleByNameRow{}, iam.ErrRoleNotFound
	}
	row, err := db.New(q).CustomRoleByName(ctx, db.CustomRoleByNameParams{GroupID: g.ID, Role: role.String()})
	if errors.Is(err, pgx.ErrNoRows) {
		return rbac.Role{}, row, iam.ErrRoleNotFound
	}
	if err != nil {
		return rbac.Role{}, row, err
	}
	r, ok := s.groupSchemaOrDefault().AssignedRole(g.Persona, role, row.Permissions)
	if !ok {
		return rbac.Role{}, row, iam.ErrRoleNotFound
	}
	return r, row, nil
}

// roleManager resolves who's authority in g and checks CAP(<p>:roles:manage)
// in a persona whose groups define custom roles.
func (s *Engine) roleManager(ctx context.Context, st *permissionGroupStore, who auth.Identity, g groupTarget) (authority, error) {
	if p, ok := s.groupSchemaOrDefault().Persona(g.Persona); !ok || !p.CustomRoles {
		return authority{}, fmt.Errorf("persona %q does not enable custom roles: %w", g.Persona, iam.ErrInsufficientAuthority)
	}
	a, err := s.identityAuthority(ctx, st, who, g)
	if err != nil {
		return authority{}, err
	}
	return a, a.requireCap(ident.RolesManage(g.Persona))
}

// editableRole refuses a role that is not a custom role of g.
func (s *Engine) editableRole(g groupTarget, role iam.Role) error {
	if role.Persona() == g.Persona && !rbac.IsCustom(role) && s.declaredRole(g.Persona, role) {
		return iam.ErrRoleNotEditable
	}
	return nil
}

// customGrants validates what a custom role of g would hold.
func (s *Engine) customGrants(g groupTarget, perms []iam.Perm) ([]string, error) {
	grants, err := s.groupSchemaOrDefault().CustomGrants(g.Persona, perms)
	if err != nil {
		return nil, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("permissions"), errmodel.WithCause(err))
	}
	return grants, nil
}

// CreateGroupRole defines a custom role in ref: CAP(<p>:roles:manage) and
// COVER of every grant. A name the group already uses is
// iam.ErrRoleExists; past iam.MaxGroupRoles, iam.ErrRoleLimitReached.
func (s *Engine) CreateGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, n iam.NewGroupRole, opts ...ops.Option) (iam.GroupRole, error) {
	host, err := hostTx("CreateGroupRole", opts)
	if err != nil {
		return iam.GroupRole{}, err
	}
	if err := requireIdentity(who); err != nil {
		return iam.GroupRole{}, err
	}
	var out iam.GroupRole
	err = s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		a, err := s.roleManager(ctx, st, who, g)
		if err != nil {
			return err
		}
		role, ok := rbac.CustomRole(g.Persona, strings.TrimSpace(n.Name))
		if !ok {
			return errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithParam("name"))
		}
		grants, err := s.customGrants(g, n.Permissions)
		if err != nil {
			return err
		}
		if err := a.requireCover(grants); err != nil {
			return err
		}
		q := db.New(st.q)
		count, err := q.CustomRoleCount(ctx, g.ID)
		if err != nil {
			return err
		}
		if count >= iam.MaxGroupRoles {
			return iam.ErrRoleLimitReached
		}
		row, err := q.CustomRoleInsert(ctx, db.CustomRoleInsertParams{GroupID: g.ID, Role: role.String(), Permissions: grants})
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.ErrRoleExists
		}
		if err != nil {
			return err
		}
		r, _ := s.groupSchemaOrDefault().AssignedRole(g.Persona, role, grants)
		out = s.groupRoleOut(g.Persona, r, &db.CustomRoleByNameRow{CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt})
		return st.record(ctx, groupRoleEvent(iam.EventGroupRoleCreated, g, role, nil, grants))
	})
	if err != nil {
		return iam.GroupRole{}, err
	}
	return out, nil
}

// UpdateGroupRole replaces what a custom role of ref grants. Every holder
// gets the change at its next request, so beyond CAP(<p>:roles:manage) and
// COVER of the grants before and after, it takes <p>:members:manage while
// members or invitations hold the role and <p>:credentials:manage while API
// keys or applications do. A change that needs MFA is refused while an API
// key or application holds the role (iam.ErrRoleNotAssignable) or a holder
// has no second factor (iam.ErrSubjectMFARequired). Afterwards every
// credential in the group (root: everywhere) whose issuer no longer covers
// its role is revoked (rule CRED).
func (s *Engine) UpdateGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, role iam.Role, u iam.GroupRoleUpdate, opts ...ops.Option) (iam.GroupRole, error) {
	host, err := hostTx("UpdateGroupRole", opts)
	if err != nil {
		return iam.GroupRole{}, err
	}
	if err := requireIdentity(who); err != nil {
		return iam.GroupRole{}, err
	}
	var out iam.GroupRole
	err = s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.editableRole(g, role); err != nil {
			return err
		}
		a, err := s.roleManager(ctx, st, who, g)
		if err != nil {
			return err
		}
		current, row, err := s.customRole(ctx, st.q, g, role)
		if err != nil {
			return err
		}
		grants, err := s.customGrants(g, u.Permissions)
		if err != nil {
			return err
		}
		holders, err := s.requireHolderAuthority(ctx, st, a, g, role, current.Permissions)
		if err != nil {
			return err
		}
		if err := a.requireCover(grants); err != nil {
			return err
		}
		if s.TwoFactorEnabled() && s.groupSchemaOrDefault().RequiresMFA(grants) {
			switch {
			case holders.Machines:
				return fmt.Errorf("role %q would need MFA, which the API keys and applications holding it cannot provide: %w", role, iam.ErrRoleNotAssignable)
			case holders.UsersWithoutMfa:
				return iam.ErrSubjectMFARequired
			}
		}
		r, _ := s.groupSchemaOrDefault().AssignedRole(g.Persona, role, grants)
		if slices.Equal(grants, row.Permissions) {
			out = s.groupRoleOut(g.Persona, r, &row)
			return nil
		}
		updated, err := db.New(st.q).CustomRoleUpdate(ctx, db.CustomRoleUpdateParams{GroupID: g.ID, Role: role.String(), Permissions: grants})
		if err != nil {
			return err
		}
		out = s.groupRoleOut(g.Persona, r, &db.CustomRoleByNameRow{CreatedAt: updated.CreatedAt, UpdatedAt: updated.UpdatedAt})
		st.touched = append(st.touched, authorityTouch{groupID: g.ID})
		return st.record(ctx, groupRoleEvent(iam.EventGroupRoleUpdated, g, role, row.Permissions, grants))
	})
	if err != nil {
		return iam.GroupRole{}, err
	}
	return out, nil
}

// DeleteGroupRole deletes a custom role of ref after taking it from every
// holder: members, applications and remote users lose it, and the API keys
// and invitations carrying it are revoked, under UpdateGroupRole's authority
// over its current grants. Deleting a role the group does not define is a
// no-op.
func (s *Engine) DeleteGroupRole(ctx context.Context, who auth.Identity, ref iam.GroupRef, role iam.Role, opts ...ops.Option) error {
	host, err := hostTx("DeleteGroupRole", opts)
	if err != nil {
		return err
	}
	if err := requireIdentity(who); err != nil {
		return err
	}
	return s.withGroupMutationIn(ctx, who, host, ref, func(st *permissionGroupStore, g groupTarget) error {
		if err := s.editableRole(g, role); err != nil {
			return err
		}
		a, err := s.roleManager(ctx, st, who, g)
		if err != nil {
			return err
		}
		current, row, err := s.customRole(ctx, st.q, g, role)
		if errors.Is(err, iam.ErrRoleNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := s.requireHolderAuthority(ctx, st, a, g, role, current.Permissions); err != nil {
			return err
		}
		q, text := db.New(st.q), role.String()
		users, err := q.CustomRoleUsersRemove(ctx, db.CustomRoleUsersRemoveParams{GroupID: g.ID, Role: text})
		if err != nil {
			return err
		}
		apps, err := q.CustomRoleApplicationsRemove(ctx, db.CustomRoleApplicationsRemoveParams{GroupID: g.ID, Role: text})
		if err != nil {
			return err
		}
		var events []iam.Event
		for _, id := range users {
			subject := iam.UserSubject(id)
			st.touch(g.ID, subject)
			events = append(events, roleEvent(g.ID, g.Persona, subject, role, iam.Role{}))
		}
		for _, id := range apps {
			events = append(events, roleEvent(g.ID, g.Persona, iam.RemoteApplicationSubject(id), role, iam.Role{}))
		}
		if err := q.CustomRoleRemoteUsersRemove(ctx, db.CustomRoleRemoteUsersRemoveParams{GroupID: g.ID, Role: text}); err != nil {
			return err
		}
		if err := q.CustomRoleCredentialsRevoke(ctx, db.CustomRoleCredentialsRevokeParams{GroupID: g.ID, Role: text}); err != nil {
			return err
		}
		if err := q.CustomRoleDelete(ctx, db.CustomRoleDeleteParams{GroupID: g.ID, Role: text}); err != nil {
			return err
		}
		return st.record(ctx, append(events, groupRoleEvent(iam.EventGroupRoleDeleted, g, role, row.Permissions, nil))...)
	})
}

// requireHolderAuthority is the authority a change to a held custom role
// takes: COVER of its current grants, and the capability that hands the role
// to each kind of holder it has.
func (s *Engine) requireHolderAuthority(ctx context.Context, st *permissionGroupStore, a authority, g groupTarget, role iam.Role, current []string) (db.CustomRoleHoldersRow, error) {
	holders, err := db.New(st.q).CustomRoleHolders(ctx, db.CustomRoleHoldersParams{GroupID: g.ID, Role: role.String()})
	if err != nil {
		return holders, err
	}
	if holders.Members {
		if err := a.requireCap(ident.MembersManage(g.Persona)); err != nil {
			return holders, err
		}
	}
	if holders.Credentials {
		if err := a.requireCap(ident.CredentialsManage(g.Persona)); err != nil {
			return holders, err
		}
	}
	return holders, a.requireCover(current)
}

// groupRoleEvent records a change to a custom role's grants.
func groupRoleEvent(kind iam.EventKind, g groupTarget, role iam.Role, previous, current []string) iam.Event {
	e := groupEvent(kind, g.ID, g.Persona)
	e.Role, e.Previous, e.Current = role, strings.Join(previous, " "), strings.Join(current, " ")
	return e
}
