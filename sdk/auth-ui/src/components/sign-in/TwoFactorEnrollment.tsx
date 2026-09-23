import { ShieldKeyIcon, SmartPhone01Icon } from "@hugeicons/core-free-icons"
import { useState } from "react"

import type { TwoFactorMethod } from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { AuthUiRoot } from "#authui/scope"
import { Button } from "#authui/ui/button"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldTitle,
} from "#authui/ui/field"
import { RadioGroup, RadioGroupItem } from "#authui/ui/radio-group"
import { useCodeBudget, useCooldown } from "./cooldown.ts"
import { normalizeIdentifier } from "./identifier.ts"
import { methodHint, methodLabel, type LoginController } from "./labels.ts"
import {
  CodeField,
  FormAlert,
  StepHeader,
  SubmitButton,
  TextButton,
  TextField,
} from "./parts.tsx"
import { TotpSetup } from "./TotpSetup.tsx"

const METHODS: readonly TwoFactorMethod[] = ["totp", "email", "sms"]

export type TwoFactorEnrollmentProps = {
  // useLogin() in its enrollment step (AuthKit requires 2FA for this account).
  controller: LoginController
  defaultPhoneCountry?: string
  onCancel?: () => void
  className?: string
}

export function TwoFactorEnrollment({
  controller,
  defaultPhoneCountry,
  onCancel,
  className,
}: TwoFactorEnrollmentProps) {
  const { t, error: describe } = useMessages()
  const { state, busy, error } = controller
  const allowed =
    state.step === "enrollment"
      ? METHODS.filter((m) => state.challenge.allowedMethods.includes(m))
      : []
  const [choice, setChoice] = useState<TwoFactorMethod | undefined>(allowed[0])
  const [phone, setPhone] = useState("")
  const [code, setCode] = useState("")
  const cooldown = useCooldown(30)
  const budget = useCodeBudget(error)
  if (state.step !== "enrollment") return null

  const started = !!state.totp || !!state.codeSent
  const spent = !!state.codeSent && budget.spent
  const confirm = (value = code) => {
    if (!value.trim() || busy) return
    setCode("")
    void controller.confirmEnrollment(value)
  }
  const start = async () => {
    if (!choice) return
    await controller.startEnrollment({
      method: choice,
      phoneNumber:
        choice === "sms"
          ? normalizeIdentifier(phone, defaultPhoneCountry)
          : undefined,
    })
    if (choice !== "totp") {
      budget.renew()
      cooldown.start()
    }
  }

  return (
    <AuthUiRoot className={className}>
      <form
        className="flex flex-col gap-5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          if (started) confirm()
          else void start()
        }}
      >
        <StepHeader
          icon={ShieldKeyIcon}
          title={t("enrollment.title")}
          description={
            state.totp
              ? t("enrollment.totpPrompt")
              : state.codeSent
                ? t("enrollment.codeSentPrompt")
                : t("twoFactor.enrollmentRequired")
          }
        />
        {error &&
          (spent ? (
            <FormAlert
              action={
                <Button
                  type="button"
                  size="sm"
                  disabled={busy}
                  onClick={() => void start()}
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
        {!allowed.length && <FormAlert>{t("enrollment.noMethod")}</FormAlert>}

        {!started && allowed.length > 0 && (
          <>
            <RadioGroup
              value={choice}
              onValueChange={(v) => setChoice(v as TwoFactorMethod)}
              aria-label={t("enrollment.chooseMethod")}
              className="gap-2"
            >
              {allowed.map((m) => (
                <FieldLabel key={m} htmlFor={`authui-enroll-${m}`}>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <FieldTitle>{methodLabel(t, m)}</FieldTitle>
                      <FieldDescription>{methodHint(t, m)}</FieldDescription>
                    </FieldContent>
                    <RadioGroupItem value={m} id={`authui-enroll-${m}`} />
                  </Field>
                </FieldLabel>
              ))}
            </RadioGroup>
            {choice === "sms" && (
              <TextField
                label={t("fields.phone")}
                icon={SmartPhone01Icon}
                type="tel"
                autoComplete="tel"
                placeholder={t("fields.phonePlaceholder")}
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
              />
            )}
            <SubmitButton
              busy={busy}
              disabled={!choice || (choice === "sms" && !phone.trim())}
            >
              {choice === "totp"
                ? t("enrollment.startTotp")
                : t("common.sendCode")}
            </SubmitButton>
          </>
        )}

        {started && (
          <>
            {state.totp && (
              <TotpSetup
                secret={state.totp.secret}
                otpauthUri={state.totp.otpauthUri}
              />
            )}
            <CodeField
              label={t("fields.verificationCode")}
              value={code}
              onChange={setCode}
              onComplete={confirm}
              invalid={!!error}
              disabled={busy}
              autoFocus={!state.totp}
            />
            <SubmitButton busy={busy} disabled={!code.trim()}>
              {t("common.verify")}
            </SubmitButton>
            {state.codeSent && !spent && (
              <TextButton
                className="self-center"
                disabled={busy || cooldown.left > 0}
                onClick={() => void start()}
              >
                {cooldown.left > 0
                  ? t("common.resendIn", { seconds: cooldown.left })
                  : t("common.resendCode")}
              </TextButton>
            )}
          </>
        )}
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={busy}
          onClick={onCancel ?? controller.reset}
        >
          {t("common.cancel")}
        </Button>
      </form>
    </AuthUiRoot>
  )
}
