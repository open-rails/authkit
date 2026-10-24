package critical_test

import (
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

func (f *fixture) ownedGroup(t *testing.T) (iam.Group, authtest.User, auth.Identity) {
	t.Helper()
	u := f.user(t)
	token := f.signIn(t, u)
	who := f.identity(t, token.AccessToken)
	subject := iam.UserSubject(u.ID)
	g, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: f.shop.Persona, Owner: &subject})
	noError(t, err)
	return g, u, who
}
func (f *fixture) grant(t *testing.T, group iam.Group, user authtest.User, role iam.Role) {
	t.Helper()
	_, err := f.auth.SetGroupRole(t.Context(), iam.SystemIdentity(), iam.GroupByID(group.ID), iam.UserSubject(user.ID), role)
	noError(t, err)
}
func (f *fixture) can(t *testing.T, who auth.Identity, group iam.Group, perm iam.Perm, want bool) {
	t.Helper()
	got, err := f.auth.Can(t.Context(), who, iam.GroupByID(group.ID), perm)
	noError(t, err)
	if got != want {
		t.Fatalf("Can(%s,%s)=%v want%v", group.ID, perm, got, want)
	}
}

func TestCriticalGroupAuthority(t *testing.T) {
	f := newFixture(t)
	t.Run("AK-J15-C01_owner_member_and_machine_permissions", func(t *testing.T) {
		g, _, owner := f.ownedGroup(t)
		member := f.user(t)
		f.grant(t, g, member, f.reader)
		memberToken := f.signIn(t, member)
		who := f.identity(t, memberToken.AccessToken)
		f.can(t, owner, g, f.write, true)
		f.can(t, who, g, f.read, true)
		f.can(t, who, g, f.write, false)
		persona, err := f.auth.Persona("shop")
		noError(t, err)
		role, err := f.auth.Role("shop:reader")
		noError(t, err)
		permission, err := f.auth.Permission("shop:orders:read")
		noError(t, err)
		if persona != g.Persona || role != f.reader || permission != f.read {
			t.Fatal("public role catalog resolved a different declared grant")
		}
		if _, err := f.auth.Persona("unknown-persona"); !errors.Is(err, iam.ErrUnknownGroupPersona) {
			t.Fatalf("unknown persona resolution:%v", err)
		}
		if _, err := f.auth.Role("shop:unknown"); !errors.Is(err, iam.ErrRoleNotAssignable) {
			t.Fatalf("unknown role resolution:%v", err)
		}
		groups, err := f.auth.Groups(t.Context(), []string{g.ID, iam.NewTenantID().String()})
		noError(t, err)
		if len(groups) != 1 || groups[g.ID].Persona != f.shop.Persona {
			t.Fatal("batch group lookup lost its known group or invented an unknown one")
		}
		page, err := f.auth.ListGroups(t.Context(), iam.GroupQuery{Persona: f.shop.Persona})
		noError(t, err)
		if !slices.ContainsFunc(page.Items, func(row iam.Group) bool { return row.ID == g.ID }) {
			t.Fatal("persona directory omitted its created group")
		}
		memberships, err := f.auth.ListMemberships(t.Context(), iam.UserSubject(member.ID), iam.PageRequest{})
		noError(t, err)
		if len(memberships.Items) != 1 || memberships.Items[0].Group.ID != g.ID || memberships.Items[0].Role != f.reader {
			t.Fatal("membership directory disagrees with the live member grant")
		}
		catalog, err := f.auth.ListGroupRoles(t.Context(), iam.GroupByID(g.ID))
		noError(t, err)
		if !slices.ContainsFunc(catalog, func(row iam.GroupRole) bool {
			return row.Name == f.reader && slices.Contains(row.Permissions, f.read) && !slices.Contains(row.Permissions, f.write)
		}) {
			t.Fatal("role catalog widened or omitted the declared reader")
		}
		expanded, err := f.auth.RolePermissions(f.reader)
		noError(t, err)
		if !slices.Contains(expanded, f.read) || slices.Contains(expanded, f.write) || !f.auth.KnownPermission(f.read) {
			t.Fatal("declared reader permission expansion is wrong")
		}
		effective, err := f.auth.EffectivePermissions(t.Context(), who, []iam.GroupRef{iam.GroupByID(g.ID)})
		noError(t, err)
		if !slices.Contains(effective[g.ID], f.read) || slices.Contains(effective[g.ID], f.write) {
			t.Fatal("effective member permissions widened the declared grant")
		}
		_, err = f.auth.SetGroupRole(t.Context(), who, iam.GroupByID(g.ID), iam.UserSubject(member.ID), f.shop.Owner)
		if !errors.Is(err, iam.ErrInsufficientAuthority) {
			t.Fatalf("member escalated its role: %v", err)
		}
		key, err := f.auth.CreateAPIKey(t.Context(), owner, iam.GroupByID(g.ID), iam.NewAPIKey{Name: "read machine", Role: f.reader})
		noError(t, err)
		machine, err := f.authenticate(t, key.Secret)
		noError(t, err)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(g.ID))
		noError(t, err)
		checker := machine.(auth.PermissionChecker)
		read, err := checker.Can(t.Context(), scope, f.read.String())
		noError(t, err)
		write, err := checker.Can(t.Context(), scope, f.write.String())
		noError(t, err)
		if !read || write || machine.Identity().Subject != g.ID {
			t.Fatal("machine authority did not retain its own group and role ceiling")
		}
	})
	t.Run("AK-J15-C02_foreign_scopes_and_fabricated_identities_are_denied", func(t *testing.T) {
		g, u, who := f.ownedGroup(t)
		other, _, _ := f.ownedGroup(t)
		f.can(t, who, other, f.read, false)
		forged := auth.Identity{Issuer: authtest.Issuer, Subject: u.ID, SubjectKind: auth.SubjectUser, TenantID: f.tenant.String()}
		f.can(t, forged, g, f.read, false)
		token := f.signIn(t, u)
		verified, err := f.authenticate(t, token.AccessToken)
		noError(t, err)
		scope, err := f.auth.Scope(t.Context(), iam.GroupByID(g.ID))
		noError(t, err)
		scope.Authority = "https://other-authority.example"
		allowed, err := verified.(auth.PermissionChecker).Can(t.Context(), scope, f.read.String())
		noError(t, err)
		if allowed {
			t.Fatal("foreign authority text was accepted as an owned scope")
		}
		_, err = f.auth.Permission("shop:orders:unknown")
		if !errors.Is(err, iam.ErrUnknownPermission) {
			t.Fatalf("unknown permission accepted: %v", err)
		}
	})
	t.Run("AK-J15-C03_custom_roles_change_live_and_declared_roles_are_immutable", func(t *testing.T) {
		g, _, owner := f.ownedGroup(t)
		member := f.user(t)
		ref := iam.GroupByID(g.ID)
		role, err := f.auth.CreateGroupRole(t.Context(), owner, ref, iam.NewGroupRole{Name: "narrow", Permissions: []iam.Perm{f.read}})
		noError(t, err)
		f.grant(t, g, member, role.Name)
		token := f.signIn(t, member)
		who := f.identity(t, token.AccessToken)
		f.can(t, who, g, f.read, true)
		f.can(t, who, g, f.write, false)
		_, err = f.auth.UpdateGroupRole(t.Context(), owner, ref, role.Name, iam.GroupRoleUpdate{Permissions: []iam.Perm{f.write}})
		noError(t, err)
		f.can(t, who, g, f.read, false)
		f.can(t, who, g, f.write, true)
		got, err := f.auth.GroupRole(t.Context(), ref, role.Name)
		noError(t, err)
		if len(got.Permissions) != 1 || got.Permissions[0] != f.write {
			t.Fatal("custom role did not read back its exact new grant")
		}
		_, err = f.auth.UpdateGroupRole(t.Context(), owner, ref, f.reader, iam.GroupRoleUpdate{Permissions: []iam.Perm{f.write}})
		if !errors.Is(err, iam.ErrRoleNotEditable) {
			t.Fatalf("declared role became editable: %v", err)
		}
		noError(t, f.auth.DeleteGroupRole(t.Context(), owner, ref, role.Name))
		f.can(t, who, g, f.write, false)
		_, err = f.auth.GroupRole(t.Context(), ref, role.Name)
		if !errors.Is(err, iam.ErrRoleNotFound) {
			t.Fatalf("deleted role remains visible: %v", err)
		}
	})
	t.Run("AK-J15-C04_concurrent_owner_removals_leave_a_usable_owner", func(t *testing.T) {
		g, first, _ := f.ownedGroup(t)
		second := f.user(t)
		f.grant(t, g, second, f.shop.Owner)
		users := []authtest.User{first, second}
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range users {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = f.auth.RemoveGroupMember(t.Context(), iam.SystemIdentity(), iam.GroupByID(g.ID), iam.UserSubject(users[i].ID))
			}()
		}
		close(start)
		wg.Wait()
		removed, refused := 0, 0
		for _, err := range errs {
			if err == nil {
				removed++
			} else if errors.Is(err, iam.ErrLastOwner) {
				refused++
			} else {
				t.Fatal(err)
			}
		}
		if removed != 1 || refused != 1 {
			t.Fatalf("owner race outcomes=%v", errs)
		}
		members, err := f.auth.ListGroupMembers(t.Context(), iam.GroupByID(g.ID), iam.MemberQuery{})
		noError(t, err)
		owners := 0
		for _, m := range members.Items {
			if m.Role == f.shop.Owner {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("committed group has %d owners", owners)
		}
	})
	t.Run("AK-J15-C05_group_lifecycle_and_reviewed_persona_migration", func(t *testing.T) {
		g, u, who := f.ownedGroup(t)
		ref := iam.GroupByID(g.ID)
		maps := map[iam.Perm]iam.Perm{f.read: f.teamRead, f.write: f.teamWrite, f.shop.Members.Read: f.team.Members.Read, f.shop.Members.Manage: f.team.Members.Manage, f.shop.Credentials.Read: f.team.Credentials.Read, f.shop.Credentials.Manage: f.team.Credentials.Manage, f.shop.Roles.Read: f.team.Roles.Read, f.shop.Roles.Manage: f.team.Roles.Manage, f.shop.Directory.Read: f.team.Directory.Read, f.shop.Directory.Manage: f.team.Directory.Manage}
		plan := iam.GroupPersonaMigration{Group: ref, From: f.shop.Persona, To: f.team.Persona, Roles: map[iam.Role]iam.Role{f.shop.Owner: f.team.Owner, f.reader: f.teamReader, f.writer: f.teamWriter}, Permissions: maps}
		preview, err := f.auth.MigrateGroupPersona(t.Context(), plan)
		noError(t, err)
		if preview.Applied || preview.Fingerprint == "" {
			t.Fatal("migration dry run did not return a read-only reviewed plan")
		}
		still, err := f.auth.Group(t.Context(), ref)
		noError(t, err)
		if still.Persona != f.shop.Persona {
			t.Fatal("dry run changed the group")
		}
		plan.Apply = true
		plan.ExpectedFingerprint = "not-the-reviewed-fingerprint"
		_, err = f.auth.MigrateGroupPersona(t.Context(), plan)
		if !errors.Is(err, iam.ErrGroupPersonaFingerprint) {
			t.Fatalf("unreviewed plan applied: %v", err)
		}
		plan.ExpectedFingerprint = preview.Fingerprint
		applied, err := f.auth.MigrateGroupPersona(t.Context(), plan)
		noError(t, err)
		if !applied.Applied {
			t.Fatal("reviewed migration did not apply")
		}
		migrated, err := f.auth.Group(t.Context(), ref)
		noError(t, err)
		if migrated.ID != g.ID || migrated.Persona != f.team.Persona {
			t.Fatal("migration changed identity or wrong persona")
		}
		f.can(t, who, migrated, f.teamRead, true)
		roles, err := f.auth.GroupRoles(t.Context(), ref, []iam.Subject{iam.UserSubject(u.ID)})
		noError(t, err)
		if roles[iam.UserSubject(u.ID)] != f.team.Owner {
			t.Fatal("owner role did not follow explicit mapping")
		}
		noError(t, f.auth.DeleteGroup(t.Context(), ref))
		f.can(t, who, migrated, f.teamRead, false)
		_, err = f.auth.Scope(t.Context(), ref)
		if !errors.Is(err, iam.ErrGroupNotFound) {
			t.Fatalf("deleted group still grants a scope: %v", err)
		}
		noError(t, f.auth.PurgeGroup(t.Context(), ref))
		_, err = f.auth.Group(t.Context(), ref)
		if !errors.Is(err, iam.ErrGroupNotFound) {
			t.Fatalf("purged group still reads: %v", err)
		}
	})
	t.Run("AK-J15-C06_transaction_rollback_and_conditional_removal", func(t *testing.T) {
		g, _, owner := f.ownedGroup(t)
		member := f.user(t)
		f.grant(t, g, member, f.reader)
		ref := iam.GroupByID(g.ID)
		subject := iam.UserSubject(member.ID)
		noError(t, f.auth.RemoveGroupMember(t.Context(), owner, ref, subject, authkit.IfRole(f.writer)))
		roles, err := f.auth.GroupRoles(t.Context(), ref, []iam.Subject{subject})
		noError(t, err)
		if roles[subject] != f.reader {
			t.Fatal("failed role precondition removed current membership")
		}
		tx, err := f.pool.Begin(t.Context())
		noError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(t.Context()) })
		_, err = f.auth.SetGroupRole(t.Context(), owner, ref, subject, f.writer, authkit.InTx(tx))
		noError(t, err)
		noError(t, tx.Rollback(t.Context()))
		roles, err = f.auth.GroupRoles(t.Context(), ref, []iam.Subject{subject})
		noError(t, err)
		if roles[subject] != f.reader {
			t.Fatal("rolled-back grant became authoritative")
		}
		_, err = f.auth.SetGroupRole(t.Context(), owner, ref, subject, f.writer)
		noError(t, err)
		got, err := f.auth.GroupRoles(t.Context(), ref, []iam.Subject{subject})
		noError(t, err)
		if got[subject] != f.writer {
			t.Fatal("committed retry did not change role")
		}
	})
	t.Run("AK-J15-C07_direct_grants_and_identity_only_verifier_remain_distinct", func(t *testing.T) {
		g, _, _ := f.ownedGroup(t)
		operator := f.user(t)
		authtest.GrantRole(t, f.auth, iam.RootGroup(), iam.UserSubject(operator.ID), f.roles.Root.Owner)
		token := f.signIn(t, operator)
		who := f.identity(t, token.AccessToken)
		f.can(t, who, g, f.read, true)
		direct, err := f.auth.CanDirect(t.Context(), who, iam.GroupByID(g.ID), f.read)
		noError(t, err)
		if direct {
			t.Fatal("root inheritance became a direct local membership")
		}
		f.grant(t, g, operator, f.reader)
		direct, err = f.auth.CanDirect(t.Context(), who, iam.GroupByID(g.ID), f.read)
		noError(t, err)
		if !direct {
			t.Fatal("explicit local grant was ignored")
		}
		v := verify.NewVerifier()
		defer v.Close()
		noError(t, v.AddIssuer(authtest.Issuer, []string{authtest.Audience}, verify.IssuerOptions{KeySource: f.deps.KeySource}))
		r, err := http.NewRequestWithContext(t.Context(), "GET", f.server.URL+"/identity", nil)
		noError(t, err)
		r.Header.Set("Authorization", "Bearer "+token.AccessToken)
		identity, err := v.AuthenticateRequest(t.Context(), r)
		noError(t, err)
		if identity.Identity().Subject != operator.ID {
			t.Fatal("stateless verifier lost authenticated identity")
		}
		if _, ok := identity.(auth.PermissionChecker); ok {
			t.Fatal("signature-only verifier fabricated live permission capability")
		}
	})
}
