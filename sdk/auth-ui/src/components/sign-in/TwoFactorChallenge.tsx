import { SecurityCheckIcon } from "@hugeicons/core-free-icons"
import { useState } from "react"

import { useMessages } from "#authui/i18n/context"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import { useCodeBudget, useCooldown } from "./cooldown.ts"
import { methodLabel, sendsCode, type LoginController } from "./labels.ts"
import {
  CodeField,
  FormAlert,
  StepHeader,
  SubmitButton,
  TextButton,
  TextField,
} from "./parts.tsx"

const RESEND_SECONDS = 30

export type TwoFactorChallengeProps = {
  // useLogin() in its two_factor step.
  controller: LoginController
  // Default: controller.reset(), back to the credentials form.
  onCancel?: () => void
  className?: string
}

export function TwoFactorChallenge({
  controller,
  onCancel,
  className,
}: TwoFactorChallengeProps) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  const [code, setCode] = useState("")
  const [backup, setBackup] = useState(false)
  const [resent, setResent] = useState(false)
  const method = state.step === "two_factor" ? state.challenge.method : ""
  const cooldown = useCooldown(RESEND_SECONDS, sendsCode(method))
  const budget = useCodeBudget(error)
  if (state.step !== "two_factor") return null

  const { challenge, factorId } = state
  const canResend = sendsCode(method) && !backup
  // A wrong code stays retryable; only a spent one needs a new code.
  const burned = canResend && budget.spent
  const others = challenge.availableFactors.filter(
    (f) => f.id && f.id !== factorId && f.method !== method
  )

  const submit = (value = code) => {
    const trimmed = value.trim()
    if (!trimmed || busy) return
    setCode("")
    setResent(false)
    void controller.verifyTwoFactor(trimmed, { backupCode: backup })
  }
  const resend = async (id?: string) => {
    setCode("")
    setResent(false)
    budget.renew()
    await controller.sendTwoFactorCode(id)
    setResent(true)
    cooldown.start()
  }
  const switchTo = (id: string) => {
    setBackup(false)
    void resend(id)
  }

  const description = backup
    ? t("twoFactor.backupPrompt")
    : method === "totp"
      ? t("twoFactor.codePromptTotp")
      : challenge.verificationId
        ? t("challenge.codeSentTo", { destination: challenge.verificationId })
        : t("twoFactor.codePrompt", { method: methodLabel(t, method) })

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
          icon={SecurityCheckIcon}
          title={t("twoFactor.challengeTitle")}
          description={description}
        />
        {error &&
          (burned ? (
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
        {backup ? (
          <TextField
            key="backup"
            label={t("twoFactor.backupCodes")}
            placeholder={t("twoFactor.backupPlaceholder")}
            autoComplete="one-time-code"
            autoCapitalize="characters"
            spellCheck={false}
            autoFocus
            name="backup-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        ) : (
          <CodeField
            key={`${method}:${challenge.challenge}`}
            label={t("fields.verificationCode")}
            value={code}
            onChange={setCode}
            onComplete={submit}
            invalid={!!error}
            disabled={busy}
          />
        )}
        <SubmitButton busy={busy} disabled={!code.trim()}>
          {busy ? t("common.verifying") : t("common.verify")}
        </SubmitButton>
        <div className="flex flex-col items-center gap-2.5 text-sm">
          {canResend && !burned && (
            <TextButton
              disabled={busy || cooldown.left > 0}
              onClick={() => void resend()}
            >
              {cooldown.left > 0
                ? t("common.resendIn", { seconds: cooldown.left })
                : t("common.resendCode")}
            </TextButton>
          )}
          <TextButton
            onClick={() => {
              setBackup((b) => !b)
              setCode("")
            }}
          >
            {backup ? t("twoFactor.useCode") : t("twoFactor.useBackup")}
          </TextButton>
          {others.map((f) => (
            <TextButton
              key={f.id}
              disabled={busy}
              onClick={() => switchTo(f.id!)}
            >
              {t("challenge.useFactor", { method: methodLabel(t, f.method) })}
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
