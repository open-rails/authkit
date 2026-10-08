import type { Capabilities } from "./types.ts"

// AuthKit's self-registration policy, /capabilities registration.mode.
export type RegistrationMode = "open" | "invite_only" | "closed"

// The advertised mode; null until capabilities are known. A value this
// package does not know reads as closed, like the server's own default.
export function registrationMode(
  capabilities: Pick<Capabilities, "registration"> | null | undefined
): RegistrationMode | null {
  const mode = capabilities?.registration.mode
  if (mode === undefined) return null
  return mode === "open" || mode === "invite_only" ? mode : "closed"
}

// Whether a visitor may create an account: always when open, only with an
// invitation code when invite_only, never when closed or still unknown.
export function registrationAvailable(
  capabilities: Pick<Capabilities, "registration"> | null | undefined,
  inviteCode?: string
): boolean {
  const mode = registrationMode(capabilities)
  return mode === "open" || (mode === "invite_only" && !!inviteCode?.trim())
}
