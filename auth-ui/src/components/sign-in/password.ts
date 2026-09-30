import type { PasswordCapabilities } from "#authui/client/types"
import { useMessages } from "#authui/i18n/context"
import { useCapabilities } from "#authui/react/context"

const PASSWORD_MIN = 8

// The shortest identifier a password may not contain (server:
// password.MinIdentifierLength).
const IDENTIFIER_MIN = 4

const CLASSES = [
  ["require_uppercase", /\p{Lu}/u],
  ["require_lowercase", /\p{Ll}/u],
  ["require_digit", /\p{Nd}/u],
  ["require_symbol", /[^\p{L}\p{Nd}]/u],
] as const

// An email is compared by its local part, anything else (username, phone)
// whole, case-insensitively.
function containsIdentifier(value: string, identifiers: string[]) {
  const lower = value.toLowerCase()
  return identifiers.some((raw) => {
    const at = raw.lastIndexOf("@")
    const id = (at > 0 ? raw.slice(0, at) : raw).trim().toLowerCase()
    return [...id].length >= IDENTIFIER_MIN && lower.includes(id)
  })
}

// Client-side mirror of the advertised policy; AuthKit stays authoritative.
// The blocklist ("password_too_common") stays server-side.
function passwordIssue(
  policy: PasswordCapabilities | undefined,
  value: string,
  identifiers: string[]
) {
  const min = policy?.min_length ?? PASSWORD_MIN
  if (value.length < min) return "password_too_short"
  if (policy && value.length > policy.max_length) return "password_too_long"
  if (CLASSES.some(([key, re]) => policy?.[key] && !re.test(value)))
    return "password_requirements_unmet"
  if (containsIdentifier(value, identifiers))
    return "password_contains_identifier"
  return null
}

// The /capabilities password policy: its minimum and the message for the
// first rule a candidate breaks (null when it passes). identifiers are the
// account's username and email/phone, when the form knows them.
export function usePasswordPolicy() {
  const { t, error: describe } = useMessages()
  const { capabilities } = useCapabilities()
  const policy = capabilities?.password
  const min = policy?.min_length ?? PASSWORD_MIN
  return {
    min,
    hint: t("register.passwordHint", { min }),
    issue: (value: string, ...identifiers: string[]) => {
      const code = passwordIssue(policy, value, identifiers)
      return !code
        ? null
        : code === "password_too_short"
          ? t("validation.passwordMinLength", { min })
          : describe(code)
    },
  }
}
