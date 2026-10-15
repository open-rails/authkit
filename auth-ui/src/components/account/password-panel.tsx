import { useEffect, useId, useState } from "react"

import { useMessages } from "../../i18n/context.ts"
import { useChangePassword } from "../../react/account.ts"
import {
  sessionIdentity,
  useAuthClient,
  useSession,
  useUser,
} from "../../react/context.ts"
import { useTask } from "../../react/task.ts"
import { Button } from "../../ui/button.tsx"
import { Card } from "../../ui/card.tsx"
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
import { ErrorNotice, Notice, SettingRow, PasswordInput } from "./shared.tsx"
import { useStepUpController } from "./step-up-context.ts"
import { PasswordUsername } from "./password-autofill.tsx"

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
  const client = useAuthClient()
  const session = useSession()
  const stepUp = useStepUpController()
  const pw = useChangePassword({ guard: stepUp?.guard })
  const preparation = useTask()
  const resetPassword = pw.reset
  const [editorOwner, setEditorOwner] = useState<string | null>(null)
  const principal = session.status === "authenticated" ? session.userId : null
  const sessionKey = sessionIdentity(session)
  const open = principal !== null && editorOwner === sessionKey
  useEffect(
    () =>
      stepUp?.guard.onResume?.("password-editor", () => {
        resetPassword()
        const current = client.getSnapshot()
        if (current.status === "authenticated")
          setEditorOwner(sessionIdentity(current))
      }),
    [stepUp?.guard, resetPassword, client]
  )
  const begin = () =>
    preparation.run(async () => {
      pw.reset()
      if (!stepUp || !principal)
        throw new Error("Sign in again to change your password.")
      await stepUp.authenticate({
        resume: { kind: "password-editor", data: null },
      })
      const current = client.getSnapshot()
      if (current.status === "authenticated" && current.userId === principal)
        setEditorOwner(sessionIdentity(current))
    })
  const hasPassword = !!user?.has_password

  return (
    <>
      <Card className="gap-0 py-0">
        <SettingRow
          title={
            <>
              {t("account.password.title")}:{" "}
              <span
                className={hasPassword ? "font-mono" : "text-muted-foreground"}
              >
                {user
                  ? hasPassword
                    ? "----"
                    : t("account.password.none")
                  : t("common.loading")}
              </span>
            </>
          }
          actions={
            <Button
              variant="outline"
              disabled={!user || preparation.busy}
              onClick={() => void begin()}
            >
              {preparation.busy && <Spinner />}
              {hasPassword
                ? t("account.password.changeTitle")
                : t("account.password.setTitle")}
            </Button>
          }
        />
        {preparation.error && (
          <div className="px-5 pb-4 sm:px-6">
            <ErrorNotice error={preparation.error} />
          </div>
        )}
        {pw.state === "done" && (
          <div className="px-5 py-4 sm:px-6">
            <Notice tone="success">
              {hasPassword
                ? t("account.password.changed")
                : t("account.password.set")}
            </Notice>
          </div>
        )}
      </Card>
      <Dialog
        open={open && pw.state !== "done"}
        onOpenChange={(next) =>
          !pw.busy && setEditorOwner(next ? sessionKey : null)
        }
      >
        <DialogContent>
          {open && pw.state !== "done" && (
            <PasswordForm
              hasPassword={hasPassword}
              busy={pw.busy}
              error={pw.error}
              onSubmit={(newPassword) => pw.changePassword({ newPassword })}
              onCancel={() => setEditorOwner(null)}
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
  const [touched, setTouched] = useState(false)
  const newId = useId()

  const policy = usePasswordPolicy()
  const issue = policy.issue(password)
  const passwordError = touched ? issue : null

  return (
    <form
      name={hasPassword ? "change-password" : "set-password"}
      method="post"
      autoComplete="on"
      aria-label={
        hasPassword
          ? t("account.password.changeTitle")
          : t("account.password.setTitle")
      }
      className="grid gap-6"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        setTouched(true)
        if (!issue) void onSubmit(password)
      }}
    >
      <PasswordUsername />
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
            name="new-password"
            autoComplete="new-password"
            required
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
