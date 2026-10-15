// Staff components for AuthKit's account and group administration.
// Customer entries never import this one.
export {
  ADMIN_ROUTES,
  createAdminClient,
  type AdminAuth,
  type AdminClient,
  type AdminClientOptions,
  type AdminRoute,
  type BanInput,
  type Page,
  type SessionEventKind,
  type UserListQuery,
  type UserUpdate,
} from "./client.ts"
export {
  useGroupAdminAccess,
  useUsersAdminAccess,
  type GroupAdminAccess,
  type UsersAdminAccess,
} from "./access.ts"
export {
  ADMIN_LANGUAGES,
  type AdminMessageBundle,
  type AdminMessageKey,
  type AdminMessageTree,
} from "./i18n.ts"
export { useHistoryNavigation, type AdminNavigation } from "./router.ts"
export type { AdminProps, GroupAdminProps } from "./root.tsx"
export {
  AuthAdmin,
  type AuthAdminProps,
  type AuthAdminSection,
} from "./console.tsx"
export { MembersAdmin, type MembersAdminProps } from "./members.tsx"
export { RolesAdmin, type RolesAdminProps } from "./roles.tsx"
export type { PermissionHelp, PermissionHelpEntry } from "./roles-lib.ts"
export { ApiKeysAdmin, type ApiKeysAdminProps } from "./api-keys.tsx"
export {
  OAuthClientsAdmin,
  type OAuthClientsAdminProps,
} from "./oauth-clients.tsx"
export {
  RemoteApplicationsAdmin,
  type RemoteApplicationsAdminProps,
} from "./remote-applications.tsx"
export { UsersAdmin, type UsersAdminProps } from "./users.tsx"
export {
  UserAccountSummary,
  type UserAccountSummaryProps,
} from "./user-summary.tsx"
export type { ConfirmWarnings, UserAction, UserPanels } from "./users-lib.ts"
