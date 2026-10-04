import { SmartPhone01Icon } from "@hugeicons/core-free-icons"
import { useState } from "react"

import { useMessages } from "#authui/i18n/context"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { useCooldown, useSpentCode } from "./cooldown.ts"
import { methodLabel, type LoginController } from "./labels.ts"
import {
  CodeField,
  FormAlert,
  StepHeader,
  SubmitButton,
  TextButton,
} from "./parts.tsx"

const RESEND_SECONDS = 30

export type NewDeviceVerificationProps = {
  // useLogin() in its new_device step.
  controller: LoginController
  // Default: controller.reset(), back to the credentials form.
  onCancel?: () => void
  className?: string
}

// A new device past the account's limit enters the code sent to the owner's
// email or phone.
export function NewDeviceVerification({
  controller,
  onCancel,
  className,
}: NewDeviceVerificationProps) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  const [code, setCode] = useState("")
  const [resent, setResent] = useState(false)
  const cooldown = useCooldown(RESEND_SECONDS, state.step === "new_device")
  const spentCode = useSpentCode(error)
  if (state.step !== "new_device") return null

  const { verification } = state
  const others = verification.channels.filter(
    (c): c is "email" | "sms" =>
      c !== verification.channel && (c === "email" || c === "sms")
  )
  const submit = (value = code) => {
    const trimmed = value.trim()
    if (!trimmed || busy) return
    setCode("")
    setResent(false)
    void controller.confirmNewDevice(trimmed)
  }
  const resend = async (channel?: "email" | "sms") => {
    setCode("")
    setResent(false)
    spentCode.renew()
    await controller.sendNewDeviceCode(channel)
    setResent(true)
    cooldown.start()
  }

  return (
    <AuthUiRoot className={className}>
      <form
        className="flex flex-col gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <StepHeader
          icon={SmartPhone01Icon}
          title={t("newDevice.title")}
          description={t("newDevice.description", {
            destination: verification.destination,
          })}
        />
        {error &&
          (spentCode.spent ? (
            <FormAlert
              action={
                <Button
                  type="button"
                  size="sm"
                  disabled={busy}
                  onClick={() => void resend()}
                >
                  {t("challenge.sendNewCode")}
                </Button>
              }
            >
              {t("challenge.codeBurned")}
            </FormAlert>
          ) : (
            <FormAlert>{describe(error)}</FormAlert>
          ))}
        {resent && !error && !busy && (
          <FormAlert tone="success">{t("challenge.codeResent")}</FormAlert>
        )}
        <CodeField
          key={`${verification.channel}:${verification.challenge}`}
          label={t("fields.verificationCode")}
          value={code}
          onChange={setCode}
          onComplete={submit}
          invalid={!!error}
          disabled={busy}
        />
        <SubmitButton busy={busy} disabled={!code.trim()}>
          {busy ? t("common.verifying") : t("common.verify")}
        </SubmitButton>
        <div className="flex flex-col items-center gap-2.5 text-sm">
          {!spentCode.spent && (
            <TextButton
              disabled={busy || cooldown.left > 0}
              onClick={() => void resend()}
            >
              {cooldown.left > 0
                ? t("common.resendIn", { seconds: cooldown.left })
                : t("common.resendCode")}
            </TextButton>
          )}
          {others.map((channel) => (
            <TextButton
              key={channel}
              disabled={busy}
              onClick={() => void resend(channel)}
            >
              {t("challenge.useFactor", { method: methodLabel(t, channel) })}
            </TextButton>
          ))}
        </div>
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={busy}
          onClick={onCancel ?? controller.reset}
        >
          {t("common.back")}
        </Button>
      </form>
    </AuthUiRoot>
  )
}
