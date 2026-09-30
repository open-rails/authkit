import { Link01Icon, LinkSquare02Icon } from "@hugeicons/core-free-icons"
import { useState, type ReactNode } from "react"

import { useMessages } from "../../i18n/context.ts"
import {
  useLinkedProviders,
  type LinkedProvider,
} from "../../react/providers.ts"
import { Button } from "../../ui/button.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { PanelRoot } from "./panel-root.tsx"
import {
  ConfirmDialog,
  Notice,
  PanelCard,
  SettingRow,
  StatusBadge,
} from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface LinkedProvidersPanelProps {
  /** Where provider linking sends the browser. Default `location.assign`. */
  navigate?: (url: string) => void
  /**
   * Extra rows, e.g. `<SolanaLinkRow>` from `@openrails/auth-ui/solana`.
   * Rendered even when no OIDC provider supports linking.
   */
  extraRows?: ReactNode
  className?: string
}

/** Link and unlink external sign-in providers listed by /capabilities. */
export function LinkedProvidersPanel({
  navigate,
  extraRows,
  className,
}: LinkedProvidersPanelProps) {
  return (
    <PanelRoot className={className}>
      <LinkedProvidersCard navigate={navigate} extraRows={extraRows} />
    </PanelRoot>
  )
}

function LinkedProvidersCard({
  navigate,
  extraRows,
}: Pick<LinkedProvidersPanelProps, "navigate" | "extraRows">) {
  const { t } = useMessages()
  const linking = useLinkedProviders({ guard: useStepUpGuard(), navigate })
  const [pending, setPending] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<LinkedProvider | null>(null)
  // The provider the last action targeted; its error renders in its row.
  const [last, setLast] = useState<string | null>(null)
  const providers = linking.providers.filter((p) => p.supportsLink || p.linked)
  if (!providers.length && !extraRows) return null

  const run = async (p: LinkedProvider, action: () => Promise<unknown>) => {
    setPending(p.id)
    setLast(p.id)
    await action()
    setPending(null)
  }

  return (
    <PanelCard
      icon={Link01Icon}
      title={t("account.providers.title")}
      description={t("account.providers.description")}
    >
      {providers.map((p) => {
        const busy = linking.busy && pending === p.id
        const error = last === p.id ? linking.error : null
        return (
          <SettingRow
            key={p.id}
            icon={LinkSquare02Icon}
            title={p.name}
            badge={
              <StatusBadge on={p.linked}>
                {p.linked
                  ? t("account.providers.linked")
                  : t("account.providers.notLinked")}
              </StatusBadge>
            }
            actions={
              p.linked ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={linking.busy}
                  onClick={() => setConfirm(p)}
                >
                  {busy && <Spinner />}
                  {busy
                    ? t("account.providers.unlinking")
                    : t("account.providers.unlink")}
                </Button>
              ) : (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={linking.busy || !p.supportsLink}
                  onClick={() => void run(p, () => linking.link(p.id))}
                >
                  {busy && <Spinner />}
                  {busy
                    ? t("account.providers.linking")
                    : t("account.providers.link")}
                </Button>
              )
            }
          >
            {error && (
              <Notice tone="error">
                <ProviderError code={error.code} err={error} />
              </Notice>
            )}
          </SettingRow>
        )
      })}
      {extraRows}
      <ConfirmDialog
        open={!!confirm}
        onOpenChange={(open) => !open && setConfirm(null)}
        title={t("account.providers.unlinkConfirmTitle", {
          provider: confirm?.name ?? "",
        })}
        description={t("account.providers.unlinkConfirmDescription", {
          provider: confirm?.name ?? "",
        })}
        confirmLabel={t("account.providers.unlink")}
        destructive
        onConfirm={() => {
          const p = confirm
          setConfirm(null)
          if (p) void run(p, () => linking.unlink(p.id))
        }}
      />
    </PanelCard>
  )
}

function ProviderError({ code, err }: { code: string; err: unknown }) {
  const { t, error } = useMessages()
  return (
    <>
      {error(err)}
      {code === "cannot_unlink_last_login_method" && (
        <span className="mt-1 block text-foreground/80">
          {t("account.providers.lastMethodHint")}
        </span>
      )}
    </>
  )
}
