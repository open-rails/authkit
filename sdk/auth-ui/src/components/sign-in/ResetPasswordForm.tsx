import {
  CheckmarkCircle02Icon,
  Key02Icon,
  Unlink01Icon,
  ResetPasswordIcon,
} from "@hugeicons/core-free-icons"
import { useState } from "react"

import { useMessages } from "#authui/i18n/context"
import { usePasswordReset } from "#authui/react/account"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { FormAlert, PasswordField, StepHeader, SubmitButton } from "./parts.tsx"

const PASSWORD_MIN = 8
const DEAD_LINK = new Set(["invalid_or_expired_token", "token_expired"])

export type ResetPasswordFormProps = {
  // From the reset link: readLinkFragment(location.hash)?.token.
  token?: string | null
  // After success, e.g. open the sign-in dialog.
  onDone?: () => void
  // Offered when the link is missing, invalid or expired.
  onRequestNewLink?: () => void
  className?: string
}

export function ResetPasswordForm({
  token,
  onDone,
  onRequestNewLink,
  className,
}: ResetPasswordFormProps) {
  const { t, error: describe } = useMessages()
  const reset = usePasswordReset({ token: token ?? undefined })
  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [touched, setTouched] = useState(false)
  const [revealed, setRevealed] = useState(false)

  if (!token || (reset.error && DEAD_LINK.has(reset.error.code)))
    return (
      <AuthUiRoot className={className}>
        <div className="flex flex-col gap-5" role="alert">
          <StepHeader
            icon={Unlink01Icon}
            title={t("resetPassword.errorTitle")}
            description={t("resetPassword.invalidLink")}
          />
          {onRequestNewLink && (
            <Button size="lg" className="w-full" onClick={onRequestNewLink}>
              {t("resetPassword.requestNewLink")}
            </Button>
          )}
        </div>
      </AuthUiRoot>
    )

  if (reset.state.step === "done")
    return (
      <AuthUiRoot className={className}>
        <div className="flex flex-col gap-5" role="status">
          <StepHeader
            icon={CheckmarkCircle02Icon}
            title={t("resetPassword.successTitle")}
            description={t("resetPassword.successDescription")}
          />
          {onDone && (
            <Button size="lg" className="w-full" autoFocus onClick={onDone}>
              {t("signIn.submit")}
            </Button>
          )}
        </div>
      </AuthUiRoot>
    )

  const passwordError =
    touched && password.length < PASSWORD_MIN
      ? t("validation.passwordMinLength", { min: PASSWORD_MIN })
      : null
  const confirmError =
    touched && !confirm
      ? t("validation.confirmPasswordRequired")
      : touched && confirm !== password
        ? t("validation.passwordsDoNotMatch")
        : null

  return (
    <AuthUiRoot className={className}>
      <form
        className="flex flex-col gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setTouched(true)
          if (password.length < PASSWORD_MIN || confirm !== password) return
          void reset.confirm({ newPassword: password })
        }}
      >
        <StepHeader
          icon={ResetPasswordIcon}
          title={t("resetPassword.title")}
          description={t("resetPassword.instructions")}
        />
        {reset.error && <FormAlert>{describe(reset.error)}</FormAlert>}
        <div className="flex flex-col gap-4">
          {/* Lets password managers file the new password under the account. */}
          <input
            type="text"
            name="username"
            autoComplete="username"
            hidden
            readOnly
          />
          <PasswordField
            label={t("fields.newPassword")}
            icon={Key02Icon}
            name="new-password"
            autoComplete="new-password"
            autoFocus
            value={password}
            error={passwordError}
            hint={t("register.passwordHint", { min: PASSWORD_MIN })}
            revealed={revealed}
            onRevealedChange={setRevealed}
            onChange={(e) => setPassword(e.target.value)}
          />
          <PasswordField
            label={t("fields.confirmPassword")}
            icon={Key02Icon}
            name="confirm-password"
            autoComplete="new-password"
            value={confirm}
            error={confirmError}
            revealed={revealed}
            onRevealedChange={setRevealed}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <SubmitButton busy={reset.busy}>
          {t("resetPassword.submit")}
        </SubmitButton>
      </form>
    </AuthUiRoot>
  )
}
