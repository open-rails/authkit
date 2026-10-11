// Staff components for AuthKit's group administration. Customer entries
// never import this one.
export {
  ADMIN_ROUTES,
  createAdminClient,
  type AdminAuth,
  type AdminClient,
  type AdminClientOptions,
  type AdminRoute,
  type Page,
} from "./client.ts"
export { useGroupAdminAccess, type GroupAdminAccess } from "./access.ts"
export {
  ADMIN_LANGUAGES,
  type AdminMessageBundle,
  type AdminMessageKey,
  type AdminMessageTree,
} from "./i18n.ts"
export { useHistoryNavigation, type AdminNavigation } from "./router.ts"
export type { AdminProps, GroupAdminProps } from "./root.tsx"
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
