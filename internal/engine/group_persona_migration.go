package engine

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/internal/tenancy"
)

type personaBinding struct {
	Kind         string          `json:"kind"`
	ID           string          `json:"id"`
	Role         string          `json:"role"`
	Creator      string          `json:"creator"`
	NeedsCreator bool            `json:"needs_creator"`
	Active       bool            `json:"active"`
	Issuer       string          `json:"issuer"`
	Meta         json.RawMessage `json:"meta"`
}

type personaCustomRole struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type personaRemote struct {
	ID      string            `json:"id"`
	RoleMap map[string]string `json:"role_map"`
	Enabled bool              `json:"enabled"`
	Issuer  string            `json:"issuer"`
}

type personaSnapshot struct {
	Group              iam.Group           `json:"group"`
	Bindings           []personaBinding    `json:"bindings"`
	CustomRoles        []personaCustomRole `json:"custom_roles"`
	RemoteApplications []personaRemote     `json:"remote_applications"`
	OAuthClients       []json.RawMessage   `json:"oauth_clients"`
	OAuthConsents      []json.RawMessage   `json:"oauth_consents"`
}

type personaPlan struct {
	report      iam.GroupPersonaMigrationReport
	snapshot    personaSnapshot
	roles       map[string]string
	definitions map[string][]string
	creators    map[string][]rbac.Assignment
}

// MigrateGroupPersona is explicit, privileged maintenance. Normal group CRUD
// never calls it. Dry-run uses a repeatable, read-only transaction; apply takes
// the authority lock before the table lock, then the individual group lock.
func (s *Engine) MigrateGroupPersona(ctx context.Context, in iam.GroupPersonaMigration) (iam.GroupPersonaMigrationReport, error) {
	var out iam.GroupPersonaMigrationReport
	if err := s.requirePG(); err != nil {
		return out, err
	}
	if in.Group.IsRoot() || in.Group.IsZero() || in.From.IsZero() || in.To.IsZero() || in.From == in.To || in.From == iam.RootPersona() || in.To == iam.RootPersona() || in.From == iam.TenantPersona() {
		return out, migrationRefusal("root, canonical tenant and same-persona transitions are not supported")
	}
	if in.Apply {
		digest, err := hex.DecodeString(in.ExpectedFingerprint)
		if err != nil || len(digest) != sha256.Size {
			return out, iam.ErrGroupPersonaFingerprint
		}
	}
	if !in.Apply {
		tx, err := s.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return out, err
		}
		defer tx.Rollback(ctx)
		plan, err := s.personaMigrationPlan(ctx, s.groupStoreFor(tx), in)
		return plan.report, err
	}
	err := s.withAuthorityMutation(ctx, iam.SystemIdentity(), func(st *permissionGroupStore) error {
		table := pgx.Identifier{s.dbSchema(), "permission_groups"}.Sanitize()
		// Take the table lock before any row lock to avoid lock upgrades against
		// a concurrent SELECT FOR UPDATE. The global authority lock comes first.
		if _, err := st.q.Exec(ctx, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
			return err
		}
		if err := lockPermissionGroup(ctx, st.q, in.Group.ID()); err != nil {
			return err
		}
		plan, err := s.personaMigrationPlan(ctx, st, in)
		out = plan.report
		if err != nil || out.AlreadyTarget {
			return err
		}
		if out.Fingerprint != in.ExpectedFingerprint {
			return iam.ErrGroupPersonaFingerprint
		}
		// ALTER is transactional. Any error rolls back both the data and this
		// one trigger's state. No tenant-ownership or other guard is disabled.
		if _, err := st.q.Exec(ctx, "ALTER TABLE "+table+" DISABLE TRIGGER permission_group_identity_immutable"); err != nil {
			return err
		}
		if err := s.applyPersonaMigration(ctx, st, in, plan); err != nil {
			return err
		}
		if _, err := st.q.Exec(ctx, "ALTER TABLE "+table+" ENABLE TRIGGER permission_group_identity_immutable"); err != nil {
			return err
		}
		// Check the actual post-state with the normal credential rules too.
		// A retained credential must not be silently revoked by a later sweep.
		for _, b := range plan.snapshot.Bindings {
			if !b.Active || !migrationCredential(b.Kind) {
				continue
			}
			c := sweptCredential{table: b.Kind, id: b.ID, creator: b.Creator, needsCreator: b.NeedsCreator,
				group: groupTarget{ID: out.GroupID, Persona: in.To, TenantID: out.TenantID}, role: ident.RoleText(plan.roles[b.Role])}
			stands, err := s.credentialStands(ctx, st, c)
			if err != nil {
				return err
			}
			if !stands {
				return migrationRefusal("a retained credential would lose its issuer authority")
			}
		}
		if err := st.record(ctx, iam.Event{Kind: iam.EventGroupPersonaMigrated, GroupID: out.GroupID, TenantID: out.TenantID, Persona: in.To, Previous: in.From.String(), Current: in.To.String()}); err != nil {
			return err
		}
		out.Applied = true
		return nil
	})
	if err != nil {
		out.Applied = false
	}
	return out, err
}

func migrationRefusal(reason string) error {
	return fmt.Errorf("%w: %s", iam.ErrGroupPersonaMigration, reason)
}

func migrationCredential(kind string) bool {
	return kind == "api_keys" || kind == "group_remote_application_roles" || kind == "group_invite_links" || kind == "account_registration_invites"
}

func (s *Engine) personaMigrationPlan(ctx context.Context, st *permissionGroupStore, in iam.GroupPersonaMigration) (personaPlan, error) {
	p := personaPlan{roles: map[string]string{}, definitions: map[string][]string{}, creators: map[string][]rbac.Assignment{}}
	p.report = iam.GroupPersonaMigrationReport{From: in.From, To: in.To, Counts: map[string]int{}, Roles: []iam.GroupPersonaRoleChange{}, Issuers: []string{}, RequiresTokenReissue: true}
	raw, err := db.New(st.q).GroupPersonaMigrationSnapshot(ctx, in.Group.ID())
	if errors.Is(err, pgx.ErrNoRows) {
		return p, iam.ErrGroupNotFound
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw, &p.snapshot); err != nil {
		return p, err
	}
	g := p.snapshot.Group
	p.report.GroupID, p.report.TenantID = g.ID, g.TenantID
	if g.DeletedAt != nil || g.TenantID.IsZero() || (g.Persona != in.From && g.Persona != in.To) {
		return p, migrationRefusal("the live group does not match the requested source or target")
	}
	if tenant, bound := tenancy.From(ctx); bound && tenant != g.TenantID {
		return p, iam.ErrTenantMismatch
	}
	if in.To == iam.TenantPersona() && g.ID != g.TenantID.String() || g.ID == g.TenantID.String() && in.To != iam.TenantPersona() {
		return p, migrationRefusal("a canonical tenant group must retain its tenant identity")
	}
	p.report.AlreadyTarget = g.Persona == in.To
	sch := s.groupSchemaOrDefault()
	from, fromKnown := sch.Persona(in.From)
	to, toKnown := sch.Persona(in.To)
	if !fromKnown || !toKnown {
		return p, migrationRefusal("both source and target catalogs must be declared")
	}
	if len(p.snapshot.RemoteApplications) > 0 && !to.RemoteApplications || len(p.snapshot.OAuthClients) > 0 && !to.OAuthClients {
		return p, migrationRefusal("the target persona does not support existing application or OAuth bindings")
	}
	if err := personaNativeOwners(g.TenantID, p.snapshot.Bindings); err != nil {
		return p, err
	}
	for _, b := range p.snapshot.Bindings {
		p.report.Counts[b.Kind]++
		if b.Kind == "api_keys" && !to.APIKeys {
			return p, migrationRefusal("the target persona does not support existing API keys")
		}
		if b.Issuer != "" && !slices.Contains(p.report.Issuers, b.Issuer) {
			p.report.Issuers = append(p.report.Issuers, b.Issuer)
		}
	}
	p.report.Counts["custom_roles"] = len(p.snapshot.CustomRoles)
	p.report.Counts["remote_applications"] = len(p.snapshot.RemoteApplications)
	p.report.Counts["oauth_clients"] = len(p.snapshot.OAuthClients)
	p.report.Counts["oauth_consents"] = len(p.snapshot.OAuthConsents)
	for _, a := range p.snapshot.RemoteApplications {
		if a.Issuer != "" && !slices.Contains(p.report.Issuers, a.Issuer) {
			p.report.Issuers = append(p.report.Issuers, a.Issuer)
		}
	}
	slices.Sort(p.report.Issuers)
	for _, issuer := range p.report.Issuers {
		if issuer != s.cfg.Token.Issuer {
			return p, migrationRefusal("a credential belongs to an unknown issuer catalog")
		}
	}
	inverseRoles := map[string]string{}
	inversePerms := map[string]string{}
	for old, next := range in.Roles {
		if old.Persona() != in.From || next.Persona() != in.To || old.IsZero() || next.IsZero() {
			return p, migrationRefusal("a role mapping has the wrong source or target persona")
		}
		if _, duplicate := inverseRoles[next.String()]; duplicate {
			return p, migrationRefusal("role mappings must be one-to-one")
		}
		p.roles[old.String()], inverseRoles[next.String()] = next.String(), old.String()
	}
	for old, next := range in.Permissions {
		if !sch.KnownPermission(old) || !sch.KnownPermission(next) {
			return p, migrationRefusal("permission mappings must name registered concrete permissions")
		}
		if _, duplicate := inversePerms[next.String()]; duplicate {
			return p, migrationRefusal("permission mappings must be one-to-one")
		}
		inversePerms[next.String()] = old.String()
	}
	custom := map[string][]string{}
	for _, c := range p.snapshot.CustomRoles {
		name, permissions := c.Role, slices.Clone(c.Permissions)
		if p.report.AlreadyTarget {
			name = inverseRoles[name]
			for i, permission := range permissions {
				permissions[i] = inversePerms[permission]
				if permissions[i] == "" {
					return p, migrationRefusal("an existing target custom grant is outside the mapping")
				}
			}
		}
		if name == "" || p.roles[name] == "" {
			return p, migrationRefusal("a custom role is not explicitly mapped")
		}
		custom[name] = permissions
	}
	var catalog []iam.Perm
	for _, persona := range sch.Personas() {
		definition, _ := sch.Persona(persona)
		catalog = append(catalog, definition.Permissions...)
	}
	oldRoles := slices.Sorted(slices.Values(mapKeys(p.roles)))
	for _, oldText := range oldRoles {
		old, next := ident.RoleText(oldText), ident.RoleText(p.roles[oldText])
		if rbac.IsCustom(old) {
			if _, err := sch.CustomGrants(in.From, ident.Perms(custom[oldText])); err != nil {
				return p, migrationRefusal("a source custom role has unknown or invalid grants")
			}
		}
		previous, ok := sch.AssignedRole(in.From, old, custom[oldText])
		if !ok {
			return p, migrationRefusal("a source role is unknown or lacks its custom definition")
		}
		var translated []iam.Perm
		for _, permission := range catalog {
			if !rbac.Covers(previous.Permissions, permission) {
				continue
			}
			mapped, ok := in.Permissions[permission]
			if !ok {
				return p, migrationRefusal("a source role permission has no explicit translation")
			}
			translated = append(translated, mapped)
		}
		var stored []string
		if rbac.IsCustom(next) {
			stored, err = sch.CustomGrants(in.To, translated)
			if err != nil {
				return p, migrationRefusal("the target custom role cannot preserve the mapped grants")
			}
			p.definitions[next.String()] = stored
		} else if rbac.IsCustom(old) {
			return p, migrationRefusal("a custom role must retain an explicitly mapped custom definition")
		}
		current, ok := sch.AssignedRole(in.To, next, stored)
		if !ok {
			return p, migrationRefusal("a target role is unknown")
		}
		if previous.RequiresMFA != current.RequiresMFA {
			return p, migrationRefusal("the target role changes MFA requirements")
		}
		for _, permission := range catalog {
			if rbac.Covers(current.Permissions, permission) != slices.Contains(translated, permission) {
				return p, migrationRefusal("the target role adds or drops mapped authority")
			}
		}
		slices.SortFunc(translated, func(a, b iam.Perm) int { return cmp.Compare(a.String(), b.String()) })
		p.report.Roles = append(p.report.Roles, iam.GroupPersonaRoleChange{From: old, To: next, Permissions: translated})
	}
	if len(p.definitions) > iam.MaxGroupRoles {
		return p, migrationRefusal("the target custom role limit would be exceeded")
	}
	checkRole := func(role string) error {
		if p.report.AlreadyTarget {
			role = inverseRoles[role]
		}
		if role == "" || p.roles[role] == "" {
			return migrationRefusal("an existing role reference has no explicit mapping")
		}
		return nil
	}
	for _, b := range p.snapshot.Bindings {
		if b.Kind == "account_registration_invites" && b.Role == "" && p.report.AlreadyTarget && in.To == iam.TenantPersona() {
			continue // A role-less tenant invitation is not a role reference.
		}
		if err := checkRole(b.Role); err != nil {
			return p, err
		}
	}
	for _, a := range p.snapshot.RemoteApplications {
		for _, role := range a.RoleMap {
			if err := checkRole(role); err != nil {
				return p, err
			}
		}
	}
	if p.report.AlreadyTarget {
		for _, c := range p.snapshot.CustomRoles {
			want := slices.Clone(p.definitions[c.Role])
			got := slices.Clone(c.Permissions)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(want, got) {
				return p, migrationRefusal("the existing target custom definition differs from the mapping")
			}
		}
	}
	if err := s.personaMigrationCreators(ctx, st, in, &p); err != nil {
		return p, err
	}
	fingerprint, err := json.Marshal(struct {
		Snapshot    personaSnapshot
		From, To    rbac.Persona
		Roles       map[iam.Role]iam.Role
		Permissions map[iam.Perm]iam.Perm
		Creators    map[string][]rbac.Assignment
	}{p.snapshot, from, to, in.Roles, in.Permissions, p.creators})
	if err != nil {
		return p, err
	}
	digest := sha256.Sum256(fingerprint)
	p.report.Fingerprint = hex.EncodeToString(digest[:])
	return p, nil
}

func personaNativeOwners(tenant iam.TenantID, bindings []personaBinding) error {
	for _, b := range bindings {
		if b.Kind != "group_user_roles" && b.Kind != "group_invite_links" && b.Kind != "account_registration_invites" {
			continue
		}
		var owner struct {
			TenantID iam.TenantID `json:"tenant_id"`
		}
		if err := json.Unmarshal(b.Meta, &owner); err != nil {
			return migrationRefusal("a native account binding has no verified tenant owner")
		}
		if owner.TenantID.IsZero() || owner.TenantID != tenant {
			return migrationRefusal("a native account binding belongs to another tenant")
		}
	}
	return nil
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}

func (s *Engine) personaMigrationCreators(ctx context.Context, st *permissionGroupStore, in iam.GroupPersonaMigration, p *personaPlan) error {
	sch := s.groupSchemaOrDefault()
	for _, binding := range p.snapshot.Bindings {
		if !binding.Active || !migrationCredential(binding.Kind) {
			continue
		}
		if binding.Kind == "account_registration_invites" && binding.Role == "" && p.report.AlreadyTarget {
			continue // This existing invitation is unaffected by a validated no-op.
		}
		roleText := p.roles[binding.Role]
		if p.report.AlreadyTarget {
			roleText = binding.Role
		}
		role, ok := sch.AssignedRole(in.To, ident.RoleText(roleText), p.definitions[roleText])
		if !ok {
			return migrationRefusal("a retained credential has an unknown target role")
		}
		machine := binding.Kind == "api_keys" || binding.Kind == "group_remote_application_roles"
		if machine && s.TwoFactorEnabled() && role.RequiresMFA {
			return migrationRefusal("a retained machine credential would require MFA")
		}
		if binding.Kind == "api_keys" {
			continue // organization-owned; the creator is audit metadata
		}
		if binding.Creator == "" {
			if binding.NeedsCreator {
				return migrationRefusal("a retained application lacks its required registrar")
			}
			continue
		}
		assignments, found := p.creators[binding.Creator]
		if !found {
			usable, _, err := userLive(ctx, st.q, binding.Creator, iam.SessionRef{})
			if err != nil {
				return err
			}
			if !usable {
				return migrationRefusal("a retained credential's issuer is not a live account")
			}
			assignments, err = st.WalkAssignments(ctx, p.report.GroupID, iam.UserSubject(binding.Creator))
			if err != nil {
				return err
			}
			for i := range assignments {
				if assignments[i].PermissionGroupID != p.report.GroupID || p.report.AlreadyTarget {
					continue
				}
				next := p.roles[assignments[i].Role.String()]
				if next == "" {
					return migrationRefusal("a credential creator's role is not mapped")
				}
				assignments[i].Persona, assignments[i].Role, assignments[i].Custom = in.To, ident.RoleText(next), p.definitions[next]
			}
			slices.SortFunc(assignments, func(a, b rbac.Assignment) int {
				return strings.Compare(a.PermissionGroupID+a.Role.String(), b.PermissionGroupID+b.Role.String())
			})
			p.creators[binding.Creator] = assignments
		}
		grants := sch.ResolveGrants(p.report.GroupID, assignments)
		capability := ident.MembersManage(in.To)
		if machine {
			capability = ident.CredentialsManage(in.To)
		}
		if !rbac.Covers(grants, capability) || !rbac.CoversAll(grants, role.Permissions) {
			return migrationRefusal("a retained credential's issuer cannot cover the translated role")
		}
	}
	return nil
}

func (s *Engine) applyPersonaMigration(ctx context.Context, st *permissionGroupStore, in iam.GroupPersonaMigration, p personaPlan) error {
	q := db.New(st.q)
	roles, err := json.Marshal(p.roles)
	if err != nil {
		return err
	}
	group := p.report.GroupID
	if err := q.GroupPersonaMigrationUsers(ctx, db.GroupPersonaMigrationUsersParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationRemoteUsers(ctx, db.GroupPersonaMigrationRemoteUsersParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationApplications(ctx, db.GroupPersonaMigrationApplicationsParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationKeys(ctx, db.GroupPersonaMigrationKeysParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationLinks(ctx, db.GroupPersonaMigrationLinksParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationInvites(ctx, db.GroupPersonaMigrationInvitesParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	if err := q.GroupPersonaMigrationRoleMaps(ctx, db.GroupPersonaMigrationRoleMapsParams{Roles: roles, GroupID: group}); err != nil {
		return err
	}
	existing := map[string]bool{}
	for _, c := range p.snapshot.CustomRoles {
		next := p.roles[c.Role]
		if err := q.GroupPersonaMigrationCustomRole(ctx, db.GroupPersonaMigrationCustomRoleParams{GroupID: group, OldRole: c.Role, NewRole: next, Permissions: p.definitions[next]}); err != nil {
			return err
		}
		existing[next] = true
	}
	for role, permissions := range p.definitions {
		if existing[role] {
			continue
		}
		if err := q.GroupPersonaMigrationInsertCustomRole(ctx, db.GroupPersonaMigrationInsertCustomRoleParams{GroupID: group, Role: role, Permissions: permissions}); err != nil {
			return err
		}
	}
	n, err := q.GroupPersonaMigrationSetPersona(ctx, db.GroupPersonaMigrationSetPersonaParams{GroupID: group, FromPersona: in.From.String(), ToPersona: in.To.String()})
	if err != nil {
		return err
	}
	if n != 1 {
		return iam.ErrGroupPersonaFingerprint
	}
	return nil
}
