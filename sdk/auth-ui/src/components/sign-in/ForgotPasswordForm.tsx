import {
  ArrowLeft01Icon,
  Mail01Icon,
  MailSend01Icon,
  ResetPasswordIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import { useState } from "react"

import { useMessages } from "#authui/i18n/context"
import { usePasswordReset } from "#authui/react/account"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { identifierKind, normalizeIdentifier } from "./identifier.ts"
import { FormAlert, StepHeader, SubmitButton, TextField } from "./parts.tsx"

export type ForgotPasswordFormProps = {
  initialIdentifier?: string
  defaultPhoneCountry?: string
  // Shows a "Back to sign in" control when given.
  onBack?: () => void
  className?: string
}

export function ForgotPasswordForm({
  initialIdentifier = "",
  defaultPhoneCountry,
  onBack,
  className,
}: ForgotPasswordFormProps) {
  const { t, error: describe } = useMessages()
  const reset = usePasswordReset()
  const [identifier, setIdentifier] = useState(initialIdentifier)
  const [touched, setTouched] = useState(false)
  const missing = touched && !identifier.trim()

  const back = onBack && (
    <Button type="button" variant="ghost" className="w-full" onClick={onBack}>
      <HugeiconsIcon icon={ArrowLeft01Icon} strokeWidth={2} />
      {t("resetPassword.backToSignIn")}
    </Button>
  )

  if (reset.state.step === "sent") {
    const phone = identifierKind(reset.state.identifier) === "phone"
    return (
      <AuthUiRoot className={className}>
        <div className="flex flex-col gap-5" role="status">
          <StepHeader
            icon={MailSend01Icon}
            title={
              phone
                ? t("resetPassword.smsSentTitle")
                : t("resetPassword.emailSentTitle")
            }
            description={
              phone
                ? t("resetPassword.smsSentDescription")
                : t("resetPassword.emailSentDescription")
            }
          />
          {back}
        </div>
      </AuthUiRoot>
    )
  }

  return (
    <AuthUiRoot className={className}>
      <form
        className="flex flex-col gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          setTouched(true)
          if (!identifier.trim()) return
          void reset.request(
            normalizeIdentifier(identifier, defaultPhoneCountry)
          )
        }}
      >
        <StepHeader
          icon={ResetPasswordIcon}
          title={t("resetPassword.requestTitle")}
          description={t("resetPassword.requestDescription")}
        />
        {reset.error && <FormAlert>{describe(reset.error)}</FormAlert>}
        <TextField
          label={t("fields.emailOrPhone")}
          icon={Mail01Icon}
          name="identifier"
          type="text"
          inputMode="email"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          autoFocus
          placeholder={t("fields.emailPlaceholder")}
          value={identifier}
          error={missing ? t("validation.emailOrPhoneRequired") : null}
          onChange={(e) => setIdentifier(e.target.value)}
        />
        <SubmitButton busy={reset.busy}>
          {reset.busy ? t("common.sending") : t("resetPassword.sendLink")}
        </SubmitButton>
        {back}
      </form>
    </AuthUiRoot>
  )
}
