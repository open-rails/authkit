import { useContext, useMemo, type ReactNode } from "react"
import { cn } from "cn"

import type { AuthUiAppearance } from "../appearance.ts"
import { MessagesContext } from "../i18n/context.ts"
import type { Guard } from "../react/task.ts"
import { AuthUiRoot } from "../scope.tsx"
import { AppearanceContext } from "../scope-context.ts"
import {
  createAdminClient,
  type AdminAuth,
  type AdminClient,
} from "./client.ts"
import { useAdminTranslator, type AdminMessageBundle } from "./i18n.ts"
import {
  createAdminRouter,
  RouterProvider,
  useHistoryNavigation,
  type AdminNavigation,
} from "./router.ts"
import { AdminContext } from "./context.ts"

/** The props every admin component takes. */
export interface AdminProps {
  /** Sends the signed-in person's credentials: auth-ui's `AuthClient` or `IssuerClient`, or anything with `authFetch`. */
  auth: AdminAuth
  /** AuthKit's JSON API mount. Default `/api/v1`. */
  baseUrl?: string
  /** Where the component is mounted; its views are deep links beneath it. */
  basePath: string
  /** The host router; the history API without one. */
  navigation?: AdminNavigation
  /** `useStepUpGuard()`: runs every write, re-authenticating when AuthKit asks. Without it a stale sign-in fails the write with "sign in again". */
  guard?: Guard
  /** Default `{ theme: "inherit" }`: the host's shadcn variables. */
  appearance?: AuthUiAppearance
  /** One of `ADMIN_LANGUAGES`; default the surrounding `AuthUiProvider`'s words. */
  language?: string
  messages?: AdminMessageBundle | readonly AdminMessageBundle[]
  className?: string
}

/** The props of a component that administers one group. */
export interface GroupAdminProps extends AdminProps {
  /** The group's id; `root` for the root group. */
  group: string
}

export function AdminRoot({
  auth,
  baseUrl,
  basePath,
  navigation,
  guard,
  appearance,
  language,
  messages,
  className,
  tenantId,
  children,
}: AdminProps & { tenantId?: string; children: ReactNode }) {
  const history = useHistoryNavigation()
  const nav = navigation ?? history
  const router = useMemo(
    () => createAdminRouter(basePath, nav),
    [basePath, nav]
  )
  const translator = useAdminTranslator(language, messages)
  const client: AdminClient = useMemo(
    () => createAdminClient({ auth, baseUrl, language, tenantId }),
    [auth, baseUrl, language, tenantId]
  )
  const host = useContext(AppearanceContext)
  const look = useMemo(
    () => ({ ...host, ...appearance, theme: appearance?.theme ?? "inherit" }),
    [host, appearance]
  )
  const scopeKey = JSON.stringify([baseUrl ?? "/api/v1", tenantId ?? null])
  const context = useMemo(
    () => ({ client, guard, tenantId, language, scopeKey }),
    [client, guard, tenantId, language, scopeKey]
  )
  return (
    <AppearanceContext.Provider value={look}>
      <MessagesContext.Provider value={translator}>
        <RouterProvider value={router}>
          <AdminContext.Provider value={context}>
            <AuthUiRoot key={scopeKey} className={cn("grid gap-6", className)}>
              {children}
            </AuthUiRoot>
          </AdminContext.Provider>
        </RouterProvider>
      </MessagesContext.Provider>
    </AppearanceContext.Provider>
  )
}
