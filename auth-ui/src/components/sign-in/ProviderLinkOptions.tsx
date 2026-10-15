import { LinkSquare02Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useCapabilities, useUser } from "../../react/context.ts"
import { useLinkedProviders } from "../../react/providers.ts"
import type { SolanaSigner } from "../../solana/core.ts"
import { SolanaLinkRow } from "../../solana/SolanaLinkRow.tsx"
import { Button } from "../../ui/button.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { ErrorNotice } from "../account/shared.tsx"
import { useStepUpGuard } from "../account/step-up-context.ts"

export type ProviderLinkOptionsProps = {
  navigate?: (url: string) => void
  acquireSolanaSigner?: () => Promise<SolanaSigner>
  onLinked?: () => void
}

/** Existing-account links only: never renders or calls sign-in/registration. */
export function ProviderLinkOptions({
  navigate,
  acquireSolanaSigner,
  onLinked,
}: ProviderLinkOptionsProps) {
  const { t } = useMessages()
  const { user } = useUser()
  const { capabilities } = useCapabilities()
  const linking = useLinkedProviders({ guard: useStepUpGuard(), navigate })
  const [pending, setPending] = useState<string | null>(null)
  const available = linking.providers.filter((p) => p.supportsLink && !p.linked)
  const wallet =
    !!capabilities?.solana?.login &&
    !!acquireSolanaSigner &&
    !user?.solana_wallet
  return (
    <div className="grid gap-3">
      {available.map((p) => (
        <Button
          key={p.id}
          variant="outline"
          size="lg"
          className="w-full"
          disabled={linking.busy || !user}
          onClick={async () => {
            setPending(p.id)
            await linking.link(p.id)
            setPending(null)
          }}
        >
          {pending === p.id ? (
            <Spinner />
          ) : (
            <HugeiconsIcon icon={LinkSquare02Icon} />
          )}
          {pending === p.id
            ? t("account.providers.linking")
            : t("account.providers.linkWith", { provider: p.name })}
        </Button>
      ))}
      {wallet && (
        <SolanaLinkRow
          display="option"
          acquireSigner={acquireSolanaSigner}
          onLinked={onLinked}
        />
      )}
      {linking.loading && (
        <span className="text-sm text-muted-foreground">
          {t("common.loading")}
        </span>
      )}
      {!linking.loading && !available.length && !wallet && (
        <p className="text-sm text-muted-foreground">
          {t("account.providers.allLinked")}
        </p>
      )}
      <ErrorNotice error={linking.error} />
    </div>
  )
}
