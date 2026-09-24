import type { PasswordPolicy } from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { useCapabilities } from "#authui/react/context"

const PASSWORD_MIN = 8

const CLASSES = [
  ["require_uppercase", /\p{Lu}/u],
  ["require_lowercase", /\p{Ll}/u],
  ["require_digit", /\p{Nd}/u],
  ["require_symbol", /[^\p{L}\p{Nd}]/u],
] as const

// Client-side mirror of the advertised policy; AuthKit stays authoritative.
function passwordIssue(policy: PasswordPolicy | undefined, value: string) {
  const min = policy?.min_length ?? PASSWORD_MIN
  if (value.length < min) return "password_too_short"
  if (policy?.max_length && value.length > policy.max_length)
    return "password_too_long"
  if (CLASSES.some(([key, re]) => policy?.[key] && !re.test(value)))
    return "password_requirements_unmet"
  return null
}

// The /capabilities password policy: its minimum and the message for the
// first rule a candidate breaks (null when it passes).
export function usePasswordPolicy() {
  const { t, error: describe } = useMessages()
  const { capabilities } = useCapabilities()
  const policy = capabilities?.password
  const min = policy?.min_length ?? PASSWORD_MIN
  return {
    min,
    hint: t("register.passwordHint", { min }),
    issue: (value: string) => {
      const code = passwordIssue(policy, value)
      return !code
        ? null
        : code === "password_too_short"
          ? t("validation.passwordMinLength", { min })
          : describe(code)
    },
  }
}
