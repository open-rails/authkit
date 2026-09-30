import { errorMetadata } from "./errors.ts"
import type { StepUpTwoFactorOptions } from "./generated/wire.ts"

export type StepUpChallenge = {
  // "password", "2fa", or a provider id that supports step-up.
  methods: string[]
  mfaRequired: boolean
  maxAgeSeconds?: number
  twoFactor?: StepUpTwoFactorOptions
}

// 403 step_up_required: re-authenticate, then retry the sensitive action.
export function readStepUpRequired(error: unknown): StepUpChallenge | null {
  const m = errorMetadata(error, "step_up_required")
  if (!m) return null
  const mfaRequired = m.mfa_required === true
  const methods = [
    ...new Set(
      (Array.isArray(m.step_up_methods) ? m.step_up_methods : [])
        .map((x) => String(x).trim().toLowerCase())
        .filter(Boolean)
    ),
  ]
  return {
    // A password alone cannot clear an MFA-gated step-up.
    methods: mfaRequired ? methods.filter((x) => x === "2fa") : methods,
    mfaRequired,
    maxAgeSeconds:
      typeof m.max_age_seconds === "number" ? m.max_age_seconds : undefined,
    twoFactor: m.step_up_2fa ?? undefined,
  }
}

// The masked address a step-up code for this method goes to, if listed.
export function stepUpDestination(
  challenge: StepUpChallenge,
  method: string
): string | null {
  return (
    challenge.twoFactor?.options?.find((o) => o.method === method)
      ?.destination ?? null
  )
}
