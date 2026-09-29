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
	"authtest/authtest.go scratchSchema":             {1, "DDL on a generated schema name; identifiers cannot be bind parameters"},
	"internal/engine/users_read.go Engine.ListUsers": {1, "filters, sort column and keyset cursor are chosen at runtime; it pages ids and loads rows with UsersByIDs"},
	// group A
	"internal/engine/account_deletion_queue.go Engine.accountDeliveryClient":          {1, pendingSQL + "A"},
	"internal/engine/account_deletion_queue.go Engine.deliverAccountEvent":            {7, pendingSQL + "A"},
	"internal/engine/account_deletion_queue.go Engine.enqueueAccountDeliveries":       {1, pendingSQL + "A"},
	"internal/engine/account_deletion_queue.go Engine.registerAccountDeliveryFleet":   {5, pendingSQL + "A"},
	"internal/engine/account_deletion_queue.go Engine.requireAccountProducerOn":       {1, pendingSQL + "A"},
	"internal/engine/account_deletion_queue.go Engine.warnUnboundAccountIssuers":      {1, pendingSQL + "A"},
	"internal/engine/account_deletion_state.go Engine.createAccountDeletion":          {1, pendingSQL + "A"},
	"internal/engine/account_deletion_state.go Engine.finalizeAccountDeletion":        {5, pendingSQL + "A"},
	"internal/engine/account_deletion_state.go Engine.requireOwnersAfterAccountPurge": {1, pendingSQL + "A"},
	"internal/engine/account_deletion_state.go loadAccountDeletion":                   {1, pendingSQL + "A"},
	"internal/engine/account_recovery_proof.go Engine.ConfirmAccountRecovery":         {1, pendingSQL + "A"},
	"internal/engine/account_recovery_proof.go Engine.bindRecoveryGeneration":         {1, pendingSQL + "A"},
	"internal/engine/account_recovery_proof.go Engine.finishRecoveryProof":            {1, pendingSQL + "A"},
	"internal/engine/account_restore.go Engine.restoreAccountDeletionOn":              {4, pendingSQL + "A"},
	"internal/engine/events.go Engine.deliverEvent":                                   {4, pendingSQL + "A"},
	"internal/engine/events.go Engine.emitEvents":                                     {2, pendingSQL + "A"},
	"internal/engine/events.go readAccountIdentity":                                   {1, pendingSQL + "A"},
	"internal/engine/host_cleanup.go Engine.cleanupExpiredAuthState":                  {1, pendingSQL + "A"},
	"internal/engine/host_cleanup.go Engine.gcTerminalAccountDeletions":               {1, pendingSQL + "A"},
	"internal/engine/river_database_identity.go requireSameRiverDatabase":             {2, pendingSQL + "A"},
	"internal/engine/session_events.go Engine.SessionEvents":                          {1, pendingSQL + "A"},
	// group B
	"internal/engine/flow_device_keys.go Engine.ActiveDeviceKeys":             {1, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.BeginDeviceKeyLogin":          {1, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.FinishDeviceKeyLogin":         {1, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.ListDeviceKeys":               {2, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.RevokeDeviceKey":              {3, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.RevokeOtherDeviceKeys":        {2, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.enrollDeviceKey":              {6, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go Engine.revokeAllDeviceKeys":          {1, pendingSQL + "B"},
	"internal/engine/flow_device_keys.go deviceKeyEnrollable":                 {1, pendingSQL + "B"},
	"internal/engine/flow_external_login.go Engine.CompleteExternalLogin":     {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.DeletePasskey":                   {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.ListPasskeys":                    {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.RenamePasskey":                   {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.insertPasskey":                   {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.passkeyCredentialsByUser":        {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.passkeyHandle":                   {2, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.passkeyUserByHandle":             {1, pendingSQL + "B"},
	"internal/engine/flow_passkeys.go Engine.updatePasskeyAfterUse":           {1, pendingSQL + "B"},
	"internal/engine/flow_solana.go Engine.VerifySIWSAndLogin":                {1, pendingSQL + "B"},
	"internal/engine/login_continuation.go Engine.holdsPasskey":               {1, pendingSQL + "B"},
	"internal/engine/login_continuation.go Engine.validateLoginProofSource":   {2, pendingSQL + "B"},
	"internal/engine/mandatory_2fa.go Engine.removeMFARequiredUserRoles":      {1, pendingSQL + "B"},
	"internal/engine/mandatory_2fa.go Engine.userHoldsMFARequiredRole":        {1, pendingSQL + "B"},
	"internal/engine/mandatory_2fa.go userHasEnabledMFA":                      {2, pendingSQL + "B"},
	"internal/engine/name_claims.go Engine.UserNamingState":                   {2, pendingSQL + "B"},
	"internal/engine/name_claims.go Engine.usernameTaken":                     {1, pendingSQL + "B"},
	"internal/engine/name_claims.go claimCanonicalName":                       {1, pendingSQL + "B"},
	"internal/engine/name_claims.go lockNameClaims":                           {1, pendingSQL + "B"},
	"internal/engine/name_claims.go renameNameClaim":                          {2, pendingSQL + "B"},
	"internal/engine/pending_change_finalizers.go Engine.finalizeChangeEmail": {1, pendingSQL + "B"},
	"internal/engine/providers.go Engine.LinkProvider":                        {1, pendingSQL + "B"},
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
	// group D
	"internal/engine/deps.go schemaPool":                                                         {1, pendingSQL + "D"},
	"internal/engine/host_bootstrap_manifest.go Engine.claimBootstrapApply":                      {2, pendingSQL + "D"},
	"internal/engine/host_bootstrap_manifest.go Engine.findBootstrapAccount":                     {2, pendingSQL + "D"},
	"internal/engine/host_ensure_user_role.go lockEnsureUser":                                    {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go Engine.importChunk":                                    {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go Engine.importHits":                                     {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go Engine.mergeImportRow":                                 {2, pendingSQL + "D"},
	"internal/engine/host_import_users.go insertImportPasswords":                                 {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go insertImportProviders":                                 {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go insertImportRows":                                      {1, pendingSQL + "D"},
	"internal/engine/host_import_users.go rejectHeldProviders":                                   {1, pendingSQL + "D"},
	"internal/engine/migration_access.go grantMigrationRuntimeAccess":                            {2, pendingSQL + "D; the GRANTs stay inline (identifiers)"},
	"internal/engine/migration_access.go migrationRuntimeUser":                                   {2, pendingSQL + "D"},
	"internal/engine/migrations.go Engine.probeMigrations":                                       {1, pendingSQL + "D"},
	"internal/engine/migrations.go Migrate":                                                      {2, pendingSQL + "D; CREATE SCHEMA stays inline (identifier)"},
	"internal/engine/remote_application_actor.go Engine.RemoteApplications":                      {1, pendingSQL + "D"},
	"internal/engine/remote_application_actor.go Engine.UpsertRemoteApplication":                 {1, pendingSQL + "D"},
	"internal/engine/remote_application_actor.go Engine.authorizeApplicationControl":             {1, pendingSQL + "D"},
	"internal/engine/remote_application_memberships.go Engine.ResolveRemoteApplicationAuthority": {1, pendingSQL + "D"},
	"internal/engine/service_remote_applications.go Engine.upsertRemoteApplication":              {1, pendingSQL + "D"},
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
