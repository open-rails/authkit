import { Delete02Icon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useId, useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useDeleteAccount } from "../../react/account.ts"
import { Button } from "../../ui/button.tsx"
import { Field, FieldDescription, FieldLabel } from "../../ui/field.tsx"
import { Input } from "../../ui/input.tsx"
import { PanelRoot } from "./panel-root.tsx"
import { ConfirmDialog, ErrorNotice, PanelCard } from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface DeleteAccountPanelProps {
  /** Runs once the account is deleted and the session has ended. */
  onDeleted?: () => void
  className?: string
}

/** Danger zone: typed confirmation, step-up, then soft delete. */
export function DeleteAccountPanel({
  onDeleted,
  className,
}: DeleteAccountPanelProps) {
  return (
    <PanelRoot className={className}>
      <DeleteAccountCard onDeleted={onDeleted} />
    </PanelRoot>
  )
}

function DeleteAccountCard({ onDeleted }: { onDeleted?: () => void }) {
  const { t } = useMessages()
  const del = useDeleteAccount({ guard: useStepUpGuard(), onDeleted })
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState("")
  const id = useId()
  const word = t("account.delete.confirmWord")
  const matches = typed.trim() === word
  const deleted = del.state === "deleted"

  return (
    <>
      <PanelCard
        tone="danger"
        icon={Delete02Icon}
        title={t("account.delete.dangerZone")}
        description={t("account.delete.description")}
        action={
          <Button
            variant="destructive"
            disabled={del.busy || deleted}
            onClick={() => {
              setTyped("")
              setOpen(true)
            }}
          >
            <HugeiconsIcon icon={Delete02Icon} strokeWidth={2} />
            {t("account.delete.submit")}
          </Button>
        }
      >
        {(del.error || deleted) && (
          <div className="px-5 py-4 sm:px-6">
            {deleted ? (
              <p role="status" className="text-sm font-medium">
                {t("account.delete.success")}
              </p>
            ) : (
              <ErrorNotice error={del.error} />
            )}
          </div>
        )}
      </PanelCard>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title={t("account.delete.title")}
        description={
          <>
            <span className="block">{t("account.delete.warningAccess")}</span>
            <span className="mt-2 block">
              {t("account.delete.warningPermanent")}
            </span>
          </>
        }
        confirmLabel={t("account.delete.submit")}
        destructive
        disabled={!matches}
        onConfirm={() => {
          if (!matches) return
          setOpen(false)
          void del.deleteAccount()
        }}
      >
        <Field>
          <FieldLabel htmlFor={id}>
            {t("account.delete.confirmLabel")}
          </FieldLabel>
          <Input
            id={id}
            autoComplete="off"
            autoFocus
            spellCheck={false}
            value={typed}
            placeholder={word}
            aria-invalid={(typed.length > 0 && !matches) || undefined}
            onChange={(e) => setTyped(e.target.value)}
          />
          <FieldDescription>
            {t("account.delete.confirmHint", { word })}
          </FieldDescription>
        </Field>
      </ConfirmDialog>
    </>
  )
}
