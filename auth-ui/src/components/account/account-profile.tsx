import { Logout01Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState, type ReactNode } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useAuthClient, useUser } from "../../react/context.ts"
import { Button } from "../../ui/button.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { AuthUiRoot } from "../../scope.tsx"
import { ErrorNotice } from "./shared.tsx"

export interface AccountProfileProps {
  avatar?: ReactNode
  username?: string
  /** The host's edit-name control, immediately beside the username. */
  nameAction?: ReactNode
  /** Account metadata such as membership status and join date. */
  children?: ReactNode
  /** Called before local sign-out, so the host can leave a protected route. */
  onSignOut?: () => void
  onSignedOut?: () => void
  className?: string
}

/** Shared account heading; avatar and application metadata remain host slots. */
export function AccountProfile({
  avatar,
  username,
  nameAction,
  children,
  onSignOut,
  onSignedOut,
  className,
}: AccountProfileProps) {
  const { t } = useMessages()
  const client = useAuthClient()
  const { user } = useUser()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const logout = async () => {
    setBusy(true)
    setError(null)
    try {
      onSignOut?.()
      await client.signOut()
      onSignedOut?.()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }
  return (
    <AuthUiRoot className={className}>
      <div className="flex items-start gap-4 sm:gap-5">
        {avatar && <div className="shrink-0">{avatar}</div>}
        <div className="grid min-w-0 flex-1 gap-3">
          <div className="flex min-w-0 items-center gap-2 sm:gap-3">
            <h2 className="min-w-0 truncate text-xl font-semibold sm:text-2xl">
              {(username ?? user?.username)?.toLowerCase() ??
                t("common.loading")}
            </h2>
            {nameAction}
            <Button
              variant="destructive"
              size="sm"
              className="ml-auto shrink-0 bg-destructive text-white hover:bg-destructive/90 dark:bg-destructive dark:hover:bg-destructive/90"
              disabled={busy}
              onClick={() => void logout()}
            >
              {busy ? <Spinner /> : <HugeiconsIcon icon={Logout01Icon} />}
              {t("account.logout")}
            </Button>
          </div>
          {children}
          <ErrorNotice error={error} />
        </div>
      </div>
    </AuthUiRoot>
  )
}
