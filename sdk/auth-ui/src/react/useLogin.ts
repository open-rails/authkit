import { useCallback, useEffect, useRef, useState } from "react"

import type { AuthOutcome } from "../client/client.ts"
import type { LoginContinuation } from "../client/continuation.ts"
import { AuthKitError } from "../client/errors.ts"
import type { AccountRecovery, TwoFactorMethod } from "../client/types.ts"
import { useAuthClient } from "./context.ts"
import { useTask } from "./task.ts"

type Continuation<K extends LoginContinuation["kind"]> = Extract<
  LoginContinuation,
  { kind: K }
>
export type TwoFactorChallenge = Continuation<"2fa_required">
export type TwoFactorEnrollmentChallenge =
  Continuation<"2fa_enrollment_required">

export type LoginState =
  | { step: "credentials"; recovered?: boolean }
  | {
      step: "two_factor"
      challenge: TwoFactorChallenge
      // Factor codes are checked against; sendTwoFactorCode(id) switches it.
      factorId?: string
    }
  | {
      step: "enrollment"
      challenge: TwoFactorEnrollmentChallenge
      // Set once startEnrollment picked a method.
      method?: TwoFactorMethod
      phoneNumber?: string
      totp?: { secret: string; otpauthUri: string }
      codeSent?: boolean
    }
  | { step: "recovery"; recovery: AccountRecovery }
  | {
      step: "verification"
      identifier: string
      channel: "email" | "phone" | null
    }
  // Signed in, but newly issued backup codes must be shown first.
  | { step: "backup_codes"; codes: string[]; returnTo?: string }
  | { step: "done"; returnTo?: string }

export type LoginOptions = {
  // Called once the session exists and any backup codes were acknowledged.
  onSignedIn?: (result: { returnTo?: string }) => void
}

// Password sign-in plus every continuation AuthKit can answer with.
export function useLogin(options: LoginOptions = {}) {
  const client = useAuthClient()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<LoginState>({ step: "credentials" })
  // Kept so account recovery can sign straight back in.
  const credentials = useRef<{ identifier: string; password: string } | null>(
    null
  )
  // Backup codes issued before a 2FA challenge (email enrollment).
  const pendingCodes = useRef<string[]>([])
  const onSignedIn = useRef(options.onSignedIn)
  useEffect(() => {
    onSignedIn.current = options.onSignedIn
  })

  const finish = useCallback((codes: string[], returnTo?: string) => {
    credentials.current = null
    pendingCodes.current = []
    if (codes.length) {
      setState({ step: "backup_codes", codes, returnTo })
      return
    }
    setState({ step: "done", returnTo })
    onSignedIn.current?.({ returnTo })
  }, [])

  const apply = useCallback(
    (outcome: AuthOutcome) => {
      switch (outcome.kind) {
        case "session":
          return finish(pendingCodes.current, outcome.returnTo)
        case "2fa_required":
          if (outcome.backupCodes.length)
            pendingCodes.current = outcome.backupCodes
          return setState({
            step: "two_factor",
            challenge: outcome,
            factorId: outcome.defaultFactor?.id,
          })
        case "2fa_enrollment_required":
          return setState({ step: "enrollment", challenge: outcome })
        case "account_recovery_required":
          return setState({ step: "recovery", recovery: outcome.recovery })
        case "verification_required":
          return setState({
            step: "verification",
            identifier: outcome.identifier,
            channel: outcome.channel,
          })
      }
    },
    [finish]
  )

  const signIn = useCallback(
    (input: { identifier: string; password: string }) =>
      run(async () => {
        credentials.current = input
        pendingCodes.current = []
        apply(await client.signInWithPassword(input))
      }),
    [client, run, apply]
  )

  // Provider sign-in in a popup; call from the click handler itself.
  // Popup failures surface as error codes popup_blocked/popup_closed/
  // popup_timeout/session_changed or the provider's code.
  const signInWithPopup = useCallback(
    (
      provider: string,
      opts: { returnTo?: string; accountInviteToken?: string } = {}
    ) =>
      run(async () => {
        credentials.current = null
        pendingCodes.current = []
        const out = await client.signInWithPopup(provider, opts)
        if (out.ok) return apply(out.outcome)
        const code =
          out.reason === "provider_error"
            ? out.code
            : out.reason === "session_changed"
              ? out.reason
              : `popup_${out.reason}`
        throw new AuthKitError(0, { type: "local", code, message: code })
      }),
    [client, run, apply]
  )

  // Enter the flow from an outcome produced elsewhere (OIDC popup/redirect,
  // registration, a refresh that now needs 2FA).
  const resume = useCallback(
    (outcome: AuthOutcome) => {
      clearError()
      apply(outcome)
    },
    [apply, clearError]
  )

  const verifyTwoFactor = useCallback(
    (code: string, opts: { backupCode?: boolean } = {}) =>
      run(async () => {
        if (state.step !== "two_factor") return
        const { challenge, factorId } = state
        apply(
          await client.verifyTwoFactor({
            userId: challenge.userId,
            challenge: challenge.challenge,
            code: code.trim(),
            factorId: opts.backupCode ? undefined : factorId,
            backupCode: opts.backupCode || undefined,
          })
        )
      }),
    [client, run, apply, state]
  )

  // Resends the current factor's code, or switches to another factor.
  const sendTwoFactorCode = useCallback(
    (factorId?: string) =>
      run(async () => {
        if (state.step !== "two_factor") return
        const target = factorId ?? state.factorId
        const next = await client.sendTwoFactorChallenge({
          userId: state.challenge.userId,
          challenge: state.challenge.challenge,
          factorId: target,
        })
        setState({ step: "two_factor", challenge: next, factorId: target })
      }),
    [client, run, state]
  )

  const enroll = useCallback(
    async (
      s: Extract<LoginState, { step: "enrollment" }>,
      input: { method: TwoFactorMethod; phoneNumber?: string; code?: string }
    ) => {
      const out = await client.enableTwoFactor(
        {
          method: input.method,
          phoneNumber: input.phoneNumber,
          code: input.code,
        },
        { enrollmentToken: s.challenge.enrollmentToken }
      )
      const base = {
        step: "enrollment" as const,
        challenge: s.challenge,
        method: input.method,
        phoneNumber: input.phoneNumber,
      }
      switch (out.kind) {
        case "totp_started":
          return setState({
            ...base,
            totp: { secret: out.secret, otpauthUri: out.otpauthUri },
          })
        case "code_sent":
          return setState({ ...base, codeSent: true })
        case "default_set":
          return setState(base)
        case "enabled":
          return finish(out.backupCodes, s.challenge.returnTo)
        default:
          return apply(out)
      }
    },
    [client, apply, finish]
  )

  // TOTP answers with a secret; SMS/email send a code.
  const startEnrollment = useCallback(
    (input: { method: TwoFactorMethod; phoneNumber?: string }) =>
      run(async () => {
        if (state.step === "enrollment") await enroll(state, input)
      }),
    [run, enroll, state]
  )

  const confirmEnrollment = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "enrollment" || !state.method) return
        await enroll(state, {
          method: state.method,
          phoneNumber: state.phoneNumber,
          code: code.trim(),
        })
      }),
    [run, enroll, state]
  )

  // Restores a soft-deleted account, then signs in again if we can.
  const confirmRecovery = useCallback(
    () =>
      run(async () => {
        if (state.step !== "recovery") return
        await client.confirmAccountRecovery(state.recovery.token)
        const again = credentials.current
        if (!again) return setState({ step: "credentials", recovered: true })
        apply(await client.signInWithPassword(again))
      }),
    [client, run, apply, state]
  )

  const resendVerification = useCallback(
    () =>
      run(async () => {
        if (state.step !== "verification") return
        await client.requestVerification({ identifier: state.identifier })
      }),
    [client, run, state]
  )

  const confirmVerification = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "verification") return
        const out = await client.confirmVerification({
          identifier: state.identifier,
          code: code.trim(),
        })
        if (out.kind !== "contact_changed") apply(out)
      }),
    [client, run, apply, state]
  )

  const acknowledgeBackupCodes = useCallback(() => {
    if (state.step !== "backup_codes") return
    setState({ step: "done", returnTo: state.returnTo })
    onSignedIn.current?.({ returnTo: state.returnTo })
  }, [state])

  const reset = useCallback(() => {
    credentials.current = null
    pendingCodes.current = []
    clearError()
    setState({ step: "credentials" })
  }, [clearError])

  return {
    state,
    busy,
    error,
    signIn,
    signInWithPopup,
    resume,
    verifyTwoFactor,
    sendTwoFactorCode,
    startEnrollment,
    confirmEnrollment,
    confirmRecovery,
    resendVerification,
    confirmVerification,
    acknowledgeBackupCodes,
    reset,
  }
}
