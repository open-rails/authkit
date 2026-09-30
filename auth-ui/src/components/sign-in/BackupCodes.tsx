import { Download01Icon, SquareLock02Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { useMessages } from "#authui/i18n/context"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { CopyButton, StepHeader } from "./parts.tsx"

export type BackupCodesProps = {
  codes: readonly string[]
  // The only way forward: hosts close the surface from here, not on session change.
  onAcknowledge: () => void
  description?: string
  className?: string
}

export function BackupCodes({
  codes,
  onAcknowledge,
  description,
  className,
}: BackupCodesProps) {
  const { t } = useMessages()
  const text = codes.join("\n")
  const download = () => {
    const body = `${t("backupCodes.fileHeader")}\n\n${text}\n`
    const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }))
    const a = document.createElement("a")
    a.href = url
    a.download = "backup-codes.txt"
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
  return (
    <AuthUiRoot className={className}>
      <div className="flex flex-col gap-5">
        <StepHeader
          icon={SquareLock02Icon}
          title={t("backupCodes.title")}
          description={description ?? t("backupCodes.signedIn")}
        />
        <ul
          aria-label={t("twoFactor.backupCodes")}
          className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-lg bg-muted px-4 py-3 text-center font-mono text-sm tracking-wider"
        >
          {codes.map((c) => (
            <li key={c} data-testid="backup-code">
              {c}
            </li>
          ))}
        </ul>
        <div className="grid grid-cols-2 gap-2">
          <CopyButton text={text} />
          <Button type="button" variant="outline" onClick={download}>
            <HugeiconsIcon icon={Download01Icon} strokeWidth={2} />
            {t("common.download")}
          </Button>
        </div>
        <Button
          type="button"
          size="lg"
          className="w-full"
          autoFocus
          onClick={onAcknowledge}
        >
          {t("backupCodes.acknowledge")}
        </Button>
      </div>
    </AuthUiRoot>
  )
}
