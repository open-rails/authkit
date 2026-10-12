import type { ReactNode } from "react"

import type { UserEntry } from "../client/generated/wire.ts"
import { Notice } from "../components/account/shared.tsx"
import { useAdminMessages } from "./i18n.ts"
import { useLoad } from "./load.ts"
import type { ConfirmWarnings, UserAction } from "./users-lib.ts"

const list = (node: ReactNode): ReactNode[] =>
  (Array.isArray(node) ? node : [node]).filter(
    (n) => n !== null && n !== undefined && n !== false && n !== ""
  )

// The host's warnings for an act on user while open; pending holds the
// confirmation until they are known.
export function useWarnings(
  warn: ConfirmWarnings | undefined,
  user: UserEntry | undefined,
  action: UserAction,
  open: boolean
): { node: ReactNode; pending: boolean } {
  const { t } = useAdminMessages()
  const loaded = useLoad(
    warn && user && open
      ? `warnings:${action}:${user.id}:${user.updated_at}`
      : null,
    async () => (warn && user ? list(await warn(user, action)) : [])
  )
  if (!warn || !user || !open) return { node: null, pending: false }
  if (loaded.loading)
    return {
      node: (
        <p role="status" className="text-sm text-muted-foreground">
          {t("users.warningsLoading")}
        </p>
      ),
      pending: true,
    }
  if (loaded.error)
    return {
      node: <Notice tone="warning">{t("users.warningsFailed")}</Notice>,
      pending: false,
    }
  return {
    node: loaded.data?.length ? (
      <div className="grid gap-2" data-slot="confirm-warnings">
        {loaded.data.map((w, i) => (
          <Notice key={i} tone="warning">
            {w}
          </Notice>
        ))}
      </div>
    ) : null,
    pending: false,
  }
}
