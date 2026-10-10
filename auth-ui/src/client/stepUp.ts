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
export function readStepUpRequired(error: unknown): StepUpChallenge | null {
  const m = errorMetadata(error, "step_up_required")
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

// A 401 asking for a fresher sign-in (RFC 9470's insufficient_user_authentication,
// AuthKit's and OpenRails' step_up_required): a refreshed token cannot clear it.
export async function asksForStepUp(res: Response): Promise<boolean> {
  if (res.status !== 401) return false
  const challenge = res.headers.get("WWW-Authenticate") ?? ""
  if (/error="insufficient_user_authentication"/.test(challenge)) return true
  const err = await readAuthKitError(res.clone()).catch(() => null)
  return err?.code === "step_up_required"
}
