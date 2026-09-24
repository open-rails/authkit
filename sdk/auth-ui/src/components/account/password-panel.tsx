import { LockPasswordIcon } from "@hugeicons/core-free-icons"
import { useId, useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useChangePassword } from "../../react/account.ts"
import { useUser } from "../../react/context.ts"
import { Button } from "../../ui/button.tsx"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../../ui/dialog.tsx"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "../../ui/field.tsx"
import { Spinner } from "../../ui/spinner.tsx"
import { usePasswordPolicy } from "../sign-in/password.ts"
import { PanelRoot } from "./panel-root.tsx"
import {
  ErrorNotice,
  Notice,
  PanelCard,
  PasswordInput,
  StatusBadge,
} from "./shared.tsx"
import { useStepUpGuard } from "./step-up-context.ts"

export interface PasswordPanelProps {
  className?: string
}

/** Set or change the password; re-authentication runs through step-up. */
export function PasswordPanel({ className }: PasswordPanelProps) {
  return (
    <PanelRoot className={className}>
      <PasswordCard />
    </PanelRoot>
  )
}

function PasswordCard() {
  const { t } = useMessages()
  const { user } = useUser()
  const pw = useChangePassword({ guard: useStepUpGuard() })
  const [open, setOpen] = useState(false)
  const hasPassword = !!user?.has_password

  return (
    <>
      <PanelCard
        icon={LockPasswordIcon}
        title={t("account.password.title")}
        badge={
          user && (
            <StatusBadge on={hasPassword}>
              {hasPassword
                ? t("account.password.isSet")
                : t("account.password.notSet")}
            </StatusBadge>
          )
        }
        description={
          hasPassword
            ? t("account.password.changeDescription")
            : t("account.password.setHint")
        }
        action={
          <Button
            variant="outline"
            disabled={!user}
            onClick={() => {
              pw.reset()
              setOpen(true)
            }}
          >
            {hasPassword
              ? t("account.password.changeTitle")
              : t("account.password.setTitle")}
          </Button>
        }
      >
        {pw.state === "done" && (
          <div className="px-5 py-4 sm:px-6">
            <Notice tone="success">
              {hasPassword
                ? t("account.password.changed")
                : t("account.password.set")}
            </Notice>
          </div>
        )}
      </PanelCard>
      <Dialog
        open={open && pw.state !== "done"}
        onOpenChange={(next) => !pw.busy && setOpen(next)}
      >
        <DialogContent>
          {open && (
            <PasswordForm
              hasPassword={hasPassword}
              busy={pw.busy}
              error={pw.error}
              onSubmit={(newPassword) => pw.changePassword({ newPassword })}
              onCancel={() => setOpen(false)}
            />
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

function PasswordForm({
  hasPassword,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  hasPassword: boolean
  busy: boolean
  error: unknown
  onSubmit: (password: string) => unknown
  onCancel: () => void
}) {
  const { t } = useMessages()
  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [touched, setTouched] = useState(false)
  const newId = useId()
  const confirmId = useId()

  const policy = usePasswordPolicy()
  const issue = policy.issue(password)
  const mismatch = confirm !== password
  const passwordError = touched ? issue : null
  const confirmError =
    touched && !issue && mismatch ? t("validation.passwordsDoNotMatch") : null

  return (
    <form
      className="grid gap-6"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        setTouched(true)
        if (!issue && !mismatch) void onSubmit(password)
      }}
    >
      <DialogHeader>
        <DialogTitle className="text-lg font-semibold">
          {hasPassword
            ? t("account.password.changeTitle")
            : t("account.password.setTitle")}
        </DialogTitle>
        <DialogDescription>
          {hasPassword
            ? t("account.password.changeDescription")
            : t("account.password.setDescription")}
        </DialogDescription>
      </DialogHeader>
      <FieldGroup className="gap-4">
        <Field data-invalid={!!passwordError || undefined}>
          <FieldLabel htmlFor={newId}>{t("fields.newPassword")}</FieldLabel>
          <PasswordInput
            id={newId}
            autoComplete="new-password"
            autoFocus
            value={password}
            disabled={busy}
            aria-invalid={!!passwordError || undefined}
            onChange={(e) => setPassword(e.target.value)}
          />
          {passwordError ? (
            <FieldError>{passwordError}</FieldError>
          ) : (
            <FieldDescription>{policy.hint}</FieldDescription>
          )}
        </Field>
        <Field data-invalid={!!confirmError || undefined}>
          <FieldLabel htmlFor={confirmId}>
            {t("fields.confirmPassword")}
          </FieldLabel>
          <PasswordInput
            id={confirmId}
            autoComplete="new-password"
            value={confirm}
            disabled={busy}
            aria-invalid={!!confirmError || undefined}
            onChange={(e) => setConfirm(e.target.value)}
          />
          <FieldError>{confirmError}</FieldError>
        </Field>
      </FieldGroup>
      <ErrorNotice error={error} />
      <DialogFooter>
        <Button
          type="button"
          variant="outline"
          disabled={busy}
          onClick={onCancel}
        >
          {t("common.cancel")}
        </Button>
        <Button type="submit" disabled={busy}>
          {busy && <Spinner />}
          {busy ? t("common.saving") : t("account.password.submit")}
        </Button>
      </DialogFooter>
    </form>
  )
}
