import {
  Add01Icon,
  Link01Icon,
  LinkSquare02Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState, type ReactNode } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useCapabilities, useUser } from "../../react/context.ts"
import {
  useLinkedProviders,
  type LinkedProvider,
} from "../../react/providers.ts"
import { Button } from "../../ui/button.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import type { SolanaSigner } from "../../solana/core.ts"
import { SolanaLinkRow } from "../../solana/SolanaLinkRow.tsx"
import { SignInDialog } from "../sign-in/SignInDialog.tsx"
import { PanelRoot } from "./panel-root.tsx"
import { ConfirmDialog, Notice, PanelCard, SettingRow } from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface LinkedProvidersPanelProps {
  /** Where provider linking sends the browser. Default `location.assign`. */
  navigate?: (url: string) => void
  /** Acquires the host's wallet for the link-only dialog and wallet verification. */
  acquireSolanaSigner?: () => Promise<SolanaSigner>
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
  acquireSolanaSigner,
  extraRows,
  className,
}: LinkedProvidersPanelProps) {
  return (
    <PanelRoot className={className}>
      <LinkedProvidersCard
        navigate={navigate}
        extraRows={extraRows}
        acquireSolanaSigner={acquireSolanaSigner}
      />
    </PanelRoot>
  )
}

function LinkedProvidersCard({
  navigate,
  extraRows,
  acquireSolanaSigner,
}: Pick<
  LinkedProvidersPanelProps,
  "navigate" | "extraRows" | "acquireSolanaSigner"
>) {
  const { t } = useMessages()
  const linking = useLinkedProviders({ guard: useStepUpGuard(), navigate })
  const { capabilities } = useCapabilities()
  const { user } = useUser()
  const [linkOpen, setLinkOpen] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<LinkedProvider | null>(null)
  // The provider the last action targeted; its error renders in its row.
  const [last, setLast] = useState<string | null>(null)
  const providers = linking.providers.filter((p) => p.linked)
  const wallet = !extraRows && !!user?.solana_wallet
  const canAdd =
    linking.providers.some((p) => p.supportsLink && !p.linked) ||
    (!!capabilities?.solana?.login &&
      !!acquireSolanaSigner &&
      !user?.solana_wallet)

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
      action={
        <Button
          variant="outline"
          size="icon"
          aria-label={t("account.providers.add")}
          disabled={linking.loading || !canAdd}
          onClick={() => setLinkOpen(true)}
        >
          <HugeiconsIcon icon={Add01Icon} />
        </Button>
      }
    >
      {providers.map((p) => {
        const busy = linking.busy && pending === p.id
        const error = last === p.id ? linking.error : null
        return (
          <SettingRow
            key={p.id}
            icon={LinkSquare02Icon}
            title={p.name}
            actions={
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
      {wallet && (
        <SolanaLinkRow display="linked" acquireSigner={acquireSolanaSigner} />
      )}
      {extraRows}
      {!providers.length && !wallet && !extraRows && (
        <p className="px-5 py-4 text-sm text-muted-foreground sm:px-6">
          {t("account.providers.noneLinked")}
        </p>
      )}
      <SignInDialog
        mode="link"
        open={linkOpen}
        onOpenChange={setLinkOpen}
        navigate={navigate}
        acquireSolanaSigner={acquireSolanaSigner}
      />
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
