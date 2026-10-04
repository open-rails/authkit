import type { AuthResult } from "./generated/wire.ts"

type Status = AuthResult["status"]

type With<S extends Status, K extends keyof AuthResult> = AuthResult & {
  status: S
} & { [P in K]-?: NonNullable<AuthResult[P]> }

// AuthResult narrowed by status: each status carries its step.
export type SignInResult =
  | With<"complete", "token_set">
  | With<"second_factor_required", "second_factor">
  | With<"enrollment_required", "enrollment">
  | With<"verification_required", "verification">
  | With<"account_recovery_required", "recovery">
  | With<"device_verification_required", "device_verification">

// A sign-in that needs one more step before it has a session.
export type PendingSignIn = Exclude<SignInResult, { status: "complete" }>

const STEP = {
  complete: "token_set",
  second_factor_required: "second_factor",
  enrollment_required: "enrollment",
  verification_required: "verification",
  account_recovery_required: "recovery",
  device_verification_required: "device_verification",
} as const satisfies Record<Status, keyof AuthResult>

// Checks an AuthKit answer is an AuthResult whose status carries its step.
export function toSignInResult(body: unknown): SignInResult {
  const result = body as AuthResult | null | undefined
  const step = result ? STEP[result.status] : undefined
  if (!result || !step || !result[step])
    throw new Error("AuthKit returned no AuthResult")
  return result as SignInResult
}
