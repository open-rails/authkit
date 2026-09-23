import type { Translator } from "#authui/i18n/messages"
import type { useLogin } from "#authui/react/useLogin"
import type { useRegister } from "#authui/react/useRegister"
import type { SignInStep } from "./SignInFlow.tsx"

export type LoginController = ReturnType<typeof useLogin>
export type RegisterController = ReturnType<typeof useRegister>

export function methodLabel(t: Translator["t"], method: string): string {
  switch (method) {
    case "email":
      return t("twoFactor.methods.email")
    case "sms":
      return t("twoFactor.methods.sms")
    case "totp":
      return t("twoFactor.methods.totp")
    default:
      return method
  }
}

export function methodHint(t: Translator["t"], method: string): string {
  switch (method) {
    case "email":
      return t("twoFactor.hints.email")
    case "sms":
      return t("twoFactor.hints.sms")
    case "totp":
      return t("twoFactor.hints.totp")
    default:
      return ""
  }
}

export const sendsCode = (method: string) =>
  method === "email" || method === "sms"

export const isEntryStep = (step: SignInStep) =>
  step === "login" || step === "register"
