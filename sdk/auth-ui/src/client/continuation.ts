import { AuthKitError } from "./errors.ts"
import type {
  AccountRecovery,
  StepUpTwoFactorOptions,
  TokenSet,
  TwoFactorFactor,
} from "./types.ts"

// A first factor that did not (yet) yield a session (authhttp writeLoginContinuation).
export type LoginContinuation =
  | {
      kind: "2fa_required"
      userId: string
      challenge: string
      method: string
      // Masked destination the code went to.
      verificationId: string
      defaultFactor?: TwoFactorFactor
      availableFactors: TwoFactorFactor[]
      // Backup codes issued alongside this challenge (shown after sign-in).
      backupCodes: string[]
      returnTo?: string
    }
  | {
      kind: "2fa_enrollment_required"
      userId: string
      allowedMethods: string[]
      // Restricted bearer: only valid for POST /user/2fa, never a session.
      enrollmentToken: TokenSet
      returnTo?: string
    }
  | { kind: "account_recovery_required"; recovery: AccountRecovery }
  | {
      kind: "verification_required"
      identifier: string
      channel: "email" | "phone" | null
    }

export type ContinuationKind = LoginContinuation["kind"]

type Rec = Record<string, unknown>

const rec = (v: unknown): Rec =>
  v !== null && typeof v === "object" ? (v as Rec) : {}
const str = (v: unknown): string => (typeof v === "string" ? v : "")
const strs = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []
const opt = (v: unknown): string | undefined => str(v) || undefined

function factor(v: unknown): TwoFactorFactor | undefined {
  const f = rec(v)
  const method = str(f.method)
  if (!method) return undefined
  return {
    id: opt(f.id),
    method,
    is_default: f.is_default === true,
    phone_number: opt(f.phone_number) ?? null,
  }
}

function tokenSet(v: unknown): TokenSet | undefined {
  const t = rec(v)
  const access = str(t.access_token)
  if (!access) return undefined
  return {
    access_token: access,
    token_type: str(t.token_type) || "Bearer",
    expires_in: typeof t.expires_in === "number" ? t.expires_in : undefined,
  }
}

// Builds a continuation from an error code plus its metadata, whichever
// transport carried them (JSON envelope, fragment, popup message).
export function continuationFrom(
  code: string,
  metadata: unknown
): LoginContinuation | null {
  const m = rec(metadata)
  switch (code) {
    case "2fa_required": {
      const userId = str(m.user_id)
      const challenge = str(m.challenge)
      if (!userId || !challenge) return null
      return {
        kind: "2fa_required",
        userId,
        challenge,
        method: str(m.method),
        verificationId: str(m.verification_id),
        defaultFactor: factor(m.default_factor),
        availableFactors: (Array.isArray(m.available_factors)
          ? m.available_factors
          : []
        )
          .map(factor)
          .filter((f): f is TwoFactorFactor => !!f),
        backupCodes: strs(m.backup_codes),
        returnTo: opt(m.return_to),
      }
    }
    case "2fa_enrollment_required": {
      const token =
        tokenSet(m.token_set) ??
        tokenSet({
          access_token: m.enrollment_token,
          expires_in:
            typeof m.enrollment_expires_in === "number"
              ? m.enrollment_expires_in
              : Number(m.enrollment_expires_in) || undefined,
        })
      if (!token) return null
      return {
        kind: "2fa_enrollment_required",
        userId: str(m.user_id),
        allowedMethods: strs(m.allowed_methods),
        enrollmentToken: token,
        returnTo: opt(m.return_to),
      }
    }
    case "account_recovery_required": {
      const r = rec(m.recovery)
      if (!str(r.token)) return null
      return {
        kind: "account_recovery_required",
        recovery: {
          token: str(r.token),
          expires_at: str(r.expires_at),
          purge_at: str(r.purge_at),
        },
      }
    }
    case "verification_required": {
      const identifier = str(m.identifier)
      if (!identifier) return null
      const channel = str(m.channel)
      return {
        kind: "verification_required",
        identifier,
        channel: channel === "email" || channel === "phone" ? channel : null,
      }
    }
    default:
      return null
  }
}

export function readContinuation(error: unknown): LoginContinuation | null {
  return error instanceof AuthKitError
    ? continuationFrom(error.code, error.metadata)
    : null
}

// Browser callbacks JSON-encode object/array params in the fragment.
export function continuationFromParams(
  params: URLSearchParams
): LoginContinuation | null {
  const metadata: Rec = {}
  for (const [key, value] of params) {
    metadata[key] = /^[[{]/.test(value) ? parseJSON(value) : value
  }
  return continuationFrom(params.get("error") ?? "", metadata)
}

function parseJSON(value: string): unknown {
  try {
    return JSON.parse(value)
  } catch {
    return value
  }
}

export type StepUpChallenge = {
  // "password", "2fa", or a provider id that supports step-up.
  methods: string[]
  mfaRequired: boolean
  maxAgeSeconds?: number
  twoFactor?: StepUpTwoFactorOptions
}

// 403 step_up_required: re-authenticate, then retry the sensitive action.
export function readStepUpRequired(error: unknown): StepUpChallenge | null {
  if (!(error instanceof AuthKitError) || error.code !== "step_up_required")
    return null
  const m = error.metadata
  const mfaRequired = m.mfa_required === true
  const methods = [
    ...new Set(
      strs(m.step_up_methods)
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean)
    ),
  ]
  return {
    // A password alone cannot clear an MFA-gated step-up.
    methods: mfaRequired ? methods.filter((x) => x === "2fa") : methods,
    mfaRequired,
    maxAgeSeconds:
      typeof m.max_age_seconds === "number" ? m.max_age_seconds : undefined,
    twoFactor: m.step_up_2fa
      ? (m.step_up_2fa as StepUpTwoFactorOptions)
      : undefined,
  }
}
