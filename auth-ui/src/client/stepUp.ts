import { errorMetadata, readAuthKitError } from "./errors.ts"
import type { TwoFactorFactor } from "./generated/wire.ts"

export type StepUpChallenge = {
  // What clears the gate: "2fa" and "passkey" for an account with a second
  // factor; otherwise "password", "passkey", "email", "sms", "solana" and
  // the providers that support step-up.
  methods: string[]
  maxAgeSeconds?: number
  // The second factors a "2fa" step-up can use, each addressed by its id.
  factors: TwoFactorFactor[]
}

// 401 step_up_required: re-authenticate, then retry the sensitive action.
// Other API clients can carry the same status, code, and metadata fields.
export function readStepUpRequired(error: unknown): StepUpChallenge | null {
  const m =
    errorMetadata(error, "step_up_required") ?? foreignStepUpMetadata(error)
  if (!m) return null
  return {
    methods: [
      ...new Set(
        (Array.isArray(m.step_up_methods) ? m.step_up_methods : [])
          .map((x) => String(x).trim().toLowerCase())
          .filter(Boolean)
      ),
    ],
    maxAgeSeconds:
      typeof m.max_age_seconds === "number" ? m.max_age_seconds : undefined,
    factors: Array.isArray(m.factors) ? m.factors : [],
  }
}

function foreignStepUpMetadata(error: unknown): {
  step_up_methods: string[]
  max_age_seconds?: number
  factors?: TwoFactorFactor[]
} | null {
  if (
    !record(error) ||
    error.status !== 401 ||
    error.code !== "step_up_required" ||
    !record(error.metadata)
  )
    return null
  const { step_up_methods, max_age_seconds, factors } = error.metadata
  if (
    !Array.isArray(step_up_methods) ||
    step_up_methods.length === 0 ||
    !step_up_methods.every(
      (method): method is string =>
        typeof method === "string" && method.trim().length > 0
    ) ||
    (max_age_seconds !== undefined &&
      (typeof max_age_seconds !== "number" ||
        !Number.isFinite(max_age_seconds) ||
        max_age_seconds < 0)) ||
    (factors !== undefined &&
      (!Array.isArray(factors) || !factors.every(factor)))
  )
    return null
  return { step_up_methods, max_age_seconds, factors }
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function factor(value: unknown): value is TwoFactorFactor {
  return (
    record(value) &&
    typeof value.id === "string" &&
    value.id.trim().length > 0 &&
    typeof value.method === "string" &&
    value.method.trim().length > 0 &&
    typeof value.is_default === "boolean" &&
    (value.destination === null || typeof value.destination === "string")
  )
}

// A 401 asking for a fresher sign-in (RFC 9470's insufficient_user_authentication,
// AuthKit's and OpenRails' step_up_required): a refreshed token cannot clear it.
export async function asksForStepUp(res: Response): Promise<boolean> {
  if (res.status !== 401) return false
  const challenge = res.headers.get("WWW-Authenticate") ?? ""
  if (/error="insufficient_user_authentication"/.test(challenge)) return true
  const err = await readAuthKitError(res.clone()).catch(() => null)
  return err?.code === "step_up_required"
}
