import type { UsernameCapabilities } from "./types.ts"

/** Checks the advertised character and length rules; the server remains
 * authoritative for availability and admission. */
export function validateUsername(
  value: string,
  policy?: UsernameCapabilities
): string | null {
  if (!policy) return null
  value = value.trim()
  if (value.length < policy.min_length) return "username_too_short"
  if (value.length > policy.max_length) return "username_too_long"
  if (/\s/u.test(value)) return "username_invalid_characters"
  try {
    if (!new RegExp(policy.pattern).test(value))
      return /^[A-Za-z]/.test(value)
        ? "username_invalid_characters"
        : "username_must_start_with_letter"
  } catch {
    return "invalid_username"
  }
  return null
}
