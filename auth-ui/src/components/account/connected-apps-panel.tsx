import { Link01Icon, LinkSquare02Icon } from "@hugeicons/core-free-icons"
import { useCallback, useEffect, useState } from "react"

import type { OAuthConsent } from "../../client/types.ts"
import { useMessages } from "../../i18n/context.ts"
import { useAuthClient } from "../../react/context.ts"
import { Button } from "../../ui/button.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { PanelRoot } from "./panel-root.tsx"
import { ConfirmDialog, ErrorNotice, PanelCard, SettingRow } from "./shared.tsx"

export interface ConnectedAppsPanelProps {
  className?: string
}

/**
 * The apps the user signed in to with this account, through groups' OAuth
 * clients ("Sign in with ..."), and disconnecting one: it loses access, its
 * refresh tokens end, and it is told. Hidden when there are none.
 */
export function ConnectedAppsPanel({ className }: ConnectedAppsPanelProps) {
  return (
    <PanelRoot className={className}>
      <ConnectedAppsCard />
    </PanelRoot>
  )
}

function ConnectedAppsCard() {
  const { t } = useMessages()
  const client = useAuthClient()
  const [apps, setApps] = useState<OAuthConsent[] | null>(null)
  const [confirm, setConfirm] = useState<OAuthConsent | null>(null)
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<unknown>(null)

  const load = useCallback(
    (signal?: AbortSignal) =>
      client.getOAuthConsents(signal).then(
        (page) => setApps(page.data),
        () => setApps([])
      ),
    [client]
  )
  useEffect(() => {
    const ctl = new AbortController()
    void load(ctl.signal)
    return () => ctl.abort()
  }, [load])

  if (!apps?.length) return null
  const disconnect = async (app: OAuthConsent) => {
    setPending(app.client_id)
    setError(null)
    try {
      await client.revokeOAuthConsent(app.client_id)
      await load()
    } catch (err) {
      setError(err)
    } finally {
      setPending(null)
    }
  }
  return (
    <PanelCard
      icon={Link01Icon}
      title={t("account.connectedApps.title")}
      description={t("account.connectedApps.description")}
    >
      {error !== null && <ErrorNotice error={error} className="mx-5 mt-4" />}
      {apps.map((app) => (
        <SettingRow
          key={app.client_id}
          icon={LinkSquare02Icon}
          title={app.group_name ?? app.client_name}
          description={t("account.connectedApps.since", {
            date: new Intl.DateTimeFormat(undefined, {
              dateStyle: "medium",
            }).format(new Date(app.granted_at)),
          })}
          actions={
            <Button
              variant="outline"
              size="sm"
              disabled={pending !== null}
              onClick={() => setConfirm(app)}
            >
              {pending === app.client_id && <Spinner />}
              {t("account.connectedApps.disconnect")}
            </Button>
          }
        />
      ))}
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={t("account.connectedApps.confirmTitle", {
          app: confirm?.group_name ?? confirm?.client_name ?? "",
        })}
        description={t("account.connectedApps.confirmDescription", {
          app: confirm?.group_name ?? confirm?.client_name ?? "",
        })}
        confirmLabel={t("account.connectedApps.disconnect")}
        destructive
        onConfirm={() => {
          const app = confirm
          setConfirm(null)
          if (app) void disconnect(app)
        }}
      />
    </PanelCard>
  )
}
