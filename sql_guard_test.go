package authkit_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sqlCallArgs are the pgx calls that carry SQL, with the SQL argument's index
// (after the context for Exec, Query and QueryRow; first for Batch.Queue).
// SendBatch and CopyFrom (-1) bypass sqlc whatever their arguments.
var sqlCallArgs = map[string]int{"Exec": 1, "Query": 1, "QueryRow": 1, "Queue": 0, "SendBatch": -1, "CopyFrom": -1}

// Outside the guard: sqlc's own package, host example programs (they own their
// tables), the browser e2e harness, and test-support packages.
func skipSQLGuardDir(path string) bool {
	switch path {
	case "internal/db", "examples", "sdk":
		return true
	}
	base := filepath.Base(path)
	return base != "." && strings.HasPrefix(base, ".") || base == "node_modules" || base == "testdata" ||
		strings.HasPrefix(path, "internal/test")
}

type inlineSQLSite struct {
	calls  int
	reason string
}

const pendingSQL = "pending #414 group "

// inlineSQL lists the functions outside internal/db that still hand SQL to
// pgx, keyed "file Func", with their call count. Static SQL belongs in
// internal/db/queries/*.sql (sqlc); only SQL built at runtime stays inline,
// with its reason here. #414 groups delete their pending entries.
var inlineSQL = map[string]inlineSQLSite{
	"authtest/authtest.go scratchSchema":                              {1, "DDL on a generated schema name; identifiers cannot be bind parameters"},
	"internal/engine/migration_access.go grantMigrationRuntimeAccess": {1, "GRANTs name the runtime role, schema and River objects; identifiers cannot be bind parameters"},
	"internal/engine/migrations.go Migrate":                           {1, "CREATE SCHEMA names the River schema; identifiers cannot be bind parameters"},
	"internal/engine/users_read.go Engine.ListUsers":                  {1, "filters, sort column and keyset cursor are chosen at runtime; it pages ids and loads rows with UsersByIDs"},
	// group C
	"internal/engine/account_registration_invites.go Engine.CreateAccountInvite":               {1, pendingSQL + "C"},
	"internal/engine/account_registration_invites.go Engine.applyRegistrationInvite":           {1, pendingSQL + "C"},
	"internal/engine/account_registration_invites.go Engine.hasValidAccountRegistrationInvite": {1, pendingSQL + "C"},
	"internal/engine/account_registration_invites.go Engine.lockRegistrationInvite":            {2, pendingSQL + "C"},
	"internal/engine/credential_issuers.go Engine.reconcileRoleCatalog":                        {2, pendingSQL + "C"},
	"internal/engine/group_roles.go Engine.GroupRoles":                                         {1, pendingSQL + "C"},
	"internal/engine/group_roles.go Engine.requireAssignableSubject":                           {2, pendingSQL + "C"},
	"internal/engine/group_roles.go Engine.requireRegistrarCover":                              {1, pendingSQL + "C"},
	"internal/engine/host_api_keys.go Engine.APIKeys":                                          {1, pendingSQL + "C"},
	"internal/engine/host_api_keys.go Engine.MintAPIKey":                                       {1, pendingSQL + "C"},
	"internal/engine/host_api_keys.go Engine.ResolveAPIKey":                                    {1, pendingSQL + "C"},
	"internal/engine/host_api_keys.go Engine.RevokeAPIKey":                                     {2, pendingSQL + "C"},
	"internal/engine/host_api_keys.go Engine.touchAccessTokenAsync":                            {1, pendingSQL + "C"},
	"internal/engine/host_group_identity.go Engine.ListGroupMembers":                           {1, pendingSQL + "C"},
	"internal/engine/host_group_identity.go Engine.ListGroups":                                 {1, pendingSQL + "C"},
	"internal/engine/host_group_identity.go Engine.ListSubjectGroups":                          {1, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go Engine.CreateInviteLink":                       {1, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go Engine.InviteLinks":                            {1, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go Engine.RedeemInviteLink":                       {3, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go Engine.RevokeInviteLink":                       {2, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go Engine.acceptAccountInvite":                    {3, pendingSQL + "C"},
	"internal/engine/host_group_invite_links.go subjectHasRole":                                {1, pendingSQL + "C"},
	"internal/engine/permission_group_lifecycle.go Engine.DeleteGroup":                         {2, pendingSQL + "C"},
	"internal/engine/permission_group_lifecycle.go Engine.requireLiveOwner":                    {1, pendingSQL + "C"},
	"internal/engine/permission_group_lifecycle.go lockPermissionGroup":                        {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.AssignRole":                {3, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.CreateGroup":               {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.DeleteGroup":               {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.OwnerCount":                {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.RootGroupID":               {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.RootRolesForUsers":         {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.groupsByID":                {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.lockGroup":                 {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.readAssignmentsForGroups":  {1, pendingSQL + "C"},
	"internal/engine/permission_group_store.go permissionGroupStore.unassign":                  {1, pendingSQL + "C"},
	"internal/engine/rbac_drift.go Engine.driftAssignedRoles":                                  {1, pendingSQL + "C"},
	// group E
	"internal/engine/account_mutations.go Engine.Ban":                                       {1, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.PatchUserMetadata":                         {1, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.PurgeUsers":                                {1, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.ResetAccountMFA":                           {2, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.Unban":                                     {1, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.applyUserUpdate":                           {5, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.passwordForUpdate":                         {1, pendingSQL + "E"},
	"internal/engine/account_mutations.go Engine.softDeleteTx":                              {1, pendingSQL + "E"},
	"internal/engine/authority.go Engine.apiKeyAuthority":                                   {1, pendingSQL + "E"},
	"internal/engine/authority.go Engine.applicationAuthority":                              {1, pendingSQL + "E"},
	"internal/engine/authority.go Engine.requireAccount":                                    {1, pendingSQL + "E"},
	"internal/engine/authority.go Engine.resolveGroup":                                      {1, pendingSQL + "E"},
	"internal/engine/authority.go permissionGroupStore.savepoint":                           {3, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.joinHostTransaction":                   {2, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.lockAuthority":                         {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.refuseOwnerLoss":                       {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.refuseSubjectOwnerLoss":                {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.requireRemainingOwner":                 {2, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.retireCredential":                      {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go Engine.revokeUncoveredCredentials":            {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go hostSavepoint.Commit":                         {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go outsideApplicationOwnerGroups":                {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go permissionGroupStore.directRoleName":          {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go subjectUsable":                                {1, pendingSQL + "E"},
	"internal/engine/authority_transaction.go userLive":                                     {1, pendingSQL + "E"},
	"internal/engine/host_permission_group_service.go permissionGroupStore.ensureRootGroup": {1, pendingSQL + "E"},
}

// Static SQL outside internal/db escapes sqlc's schema check and grows a
// second row mapping; this keeps new inline SQL out (#414).
func TestNoInlineSQL(t *testing.T) {
	found := map[string]int{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		path = filepath.ToSlash(path)
		if d.IsDir() {
			if skipSQLGuardDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			name := declName(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if arg, ok := sqlCallArgs[sel.Sel.Name]; ok && len(call.Args) > arg {
					found[path+" "+name]++
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	for key, n := range found {
		site, ok := inlineSQL[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: %d inline SQL call(s): move the SQL to internal/db/queries (sqlc)", key, n))
		case n != site.calls:
			problems = append(problems, fmt.Sprintf("%s: %d inline SQL calls, %d allowlisted", key, n, site.calls))
		}
	}
	for key := range inlineSQL {
		if found[key] == 0 {
			problems = append(problems, key+": allowlisted but has no inline SQL: delete the entry")
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("SQL outside internal/db must go through sqlc; only SQL built at runtime stays inline, allowlisted with its reason:\n  %s",
			strings.Join(problems, "\n  "))
	}
}

func declName(decl ast.Decl) string {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return "package"
	}
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	switch r := recv.(type) {
	case *ast.IndexExpr:
		recv = r.X
	case *ast.IndexListExpr:
		recv = r.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
