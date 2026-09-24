import {
  CheckmarkCircle02Icon,
  MailSend01Icon,
  UserCheck01Icon,
} from "@hugeicons/core-free-icons"
import { useState } from "react"

import { useMessages } from "#authui/i18n/context"
import { Button } from "#authui/ui/button"
import { BackupCodes } from "./BackupCodes.tsx"
import { useCooldown } from "./cooldown.ts"
import type { LoginController } from "./labels.ts"
import {
  CodeField,
  FormAlert,
  StepHeader,
  SubmitButton,
  TextButton,
} from "./parts.tsx"
import { TwoFactorChallenge } from "./TwoFactorChallenge.tsx"
import { TwoFactorEnrollment } from "./TwoFactorEnrollment.tsx"

function AccountRecovery({ controller }: { controller: LoginController }) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  if (state.step !== "recovery") return null
  const date = new Date(state.recovery.purge_at)
  const until = Number.isNaN(date.getTime())
    ? state.recovery.purge_at
    : new Intl.DateTimeFormat(undefined, { dateStyle: "long" }).format(date)
  return (
    <div className="flex flex-col gap-5">
      <StepHeader
        icon={UserCheck01Icon}
        title={t("recovery.title")}
        description={t("recovery.description", { date: until })}
      />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      <Button
        size="lg"
        className="w-full"
        disabled={busy}
        onClick={() => void controller.confirmRecovery()}
      >
        {t("recovery.confirm")}
      </Button>
      <Button
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={controller.reset}
      >
        {t("common.cancel")}
      </Button>
    </div>
  )
}

function VerificationRequired({ controller }: { controller: LoginController }) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  const [code, setCode] = useState("")
  const [sent, setSent] = useState(false)
  const cooldown = useCooldown(30)
  if (state.step !== "verification") return null
  const verify = (value = code) => {
    if (!value.trim() || busy) return
    setCode("")
    void controller.confirmVerification(value)
  }
  const resend = async () => {
    await controller.resendVerification()
    setSent(true)
    cooldown.start()
  }
  return (
    <form
      className="flex flex-col gap-5"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        verify()
      }}
    >
      <StepHeader
        icon={MailSend01Icon}
        title={
          state.channel === "phone"
            ? t("verify.titlePhone")
            : state.channel === "email"
              ? t("verify.titleEmail")
              : t("verify.title")
        }
        description={`${t("verify.pleaseVerify")} ${t("verify.codeSentTo", { destination: state.identifier })}`}
      />
      {error && <FormAlert>{describe(error)}</FormAlert>}
      {sent && !error && !busy && (
        <FormAlert tone="success">{t("verify.codeSent")}</FormAlert>
      )}
      <CodeField
        label={t("fields.verificationCode")}
        value={code}
        onChange={setCode}
        onComplete={verify}
        invalid={!!error}
        disabled={busy}
      />
      <SubmitButton busy={busy} disabled={!code.trim()}>
        {t("common.verify")}
      </SubmitButton>
      <p className="flex items-center justify-center gap-1.5 text-sm text-muted-foreground">
        {t("verify.didntReceive")}
        <TextButton
          disabled={busy || cooldown.left > 0}
          onClick={() => void resend()}
        >
          {cooldown.left > 0
            ? t("common.resendIn", { seconds: cooldown.left })
            : t("verify.resend")}
        </TextButton>
      </p>
      <Button
        type="button"
        variant="ghost"
        className="w-full"
        disabled={busy}
        onClick={controller.reset}
      >
        {t("common.back")}
      </Button>
    </form>
  )
}

// Every useLogin step after the credentials form.
export function LoginSteps({
  controller,
  defaultPhoneCountry,
}: {
  controller: LoginController
  defaultPhoneCountry?: string
}) {
  const { t } = useMessages()
  const { state } = controller
  switch (state.step) {
    case "two_factor":
      return <TwoFactorChallenge controller={controller} />
    case "enrollment":
      return (
        <TwoFactorEnrollment
          controller={controller}
          defaultPhoneCountry={defaultPhoneCountry}
        />
      )
    case "recovery":
      return <AccountRecovery controller={controller} />
    case "verification":
      return <VerificationRequired controller={controller} />
    case "backup_codes":
      return (
        <BackupCodes
          codes={state.codes}
          onAcknowledge={controller.acknowledgeBackupCodes}
        />
      )
    case "done":
      return (
        <div role="status">
          <StepHeader
            icon={CheckmarkCircle02Icon}
            title={t("signIn.success")}
          />
        </div>
      )
    default:
      return null
  }
}
