import { useCallback, useEffect, useRef, useState } from "react"

import { readStepUpRequired } from "../client/continuation.ts"
import type { StepUpChallenge } from "../client/continuation.ts"
import { AuthKitError } from "../client/errors.ts"
import { useAuthClient } from "./context.ts"
import { useTask, type Guard } from "./task.ts"

export type StepUpState =
  | { step: "idle" }
  | { step: "required"; challenge: StepUpChallenge }
  | {
      step: "code_sent"
      challenge: StepUpChallenge
      method: string
      // Masked destination the code went to.
      verificationId: string
    }

export type StepUpOptions = {
  // Where OIDC step-up sends the browser. Default location.assign.
  navigate?: (url: string) => void
}

type Waiter = {
  action: () => Promise<unknown>
  resolve: (value: unknown) => void
  reject: (error: unknown) => void
}

const cancelled = () =>
  new AuthKitError(0, {
    type: "local",
    code: "step_up_cancelled",
    message: "Step-up was cancelled.",
  })

const challengeOf = (s: StepUpState): StepUpChallenge =>
  s.step === "idle" ? { methods: ["2fa"], mfaRequired: false } : s.challenge

export function useStepUp(options: StepUpOptions = {}) {
  const client = useAuthClient()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<StepUpState>({ step: "idle" })
  const waiters = useRef<Waiter[]>([])
  const navigate = useRef(options.navigate)
  useEffect(() => {
    navigate.current = options.navigate
  })

  const settle = useCallback((ok: boolean) => {
    const pending = waiters.current
    waiters.current = []
    setState({ step: "idle" })
    for (const w of pending) {
      if (ok) w.action().then(w.resolve, w.reject)
      else w.reject(cancelled())
    }
  }, [])

  useEffect(() => () => settle(false), [settle])

  // Runs a sensitive action; on 403 step_up_required it waits for the user to
  // step up, then retries. Rejects with code "step_up_cancelled" on cancel().
  const guard: Guard = useCallback(<T>(action: () => Promise<T>) => {
    return action().catch((err: unknown) => {
      const challenge = readStepUpRequired(err)
      if (!challenge) throw err
      return new Promise<T>((resolve, reject) => {
        waiters.current.push({
          action,
          resolve: resolve as (value: unknown) => void,
          reject,
        })
        setState((s) =>
          s.step === "idle" ? { step: "required", challenge } : s
        )
      })
    })
  }, [])

  // Opens the step-up without an action, e.g. from a known challenge.
  const open = useCallback((challenge: StepUpChallenge) => {
    setState({ step: "required", challenge })
  }, [])

  const withPassword = useCallback(
    (password: string) =>
      run(async () => {
        await client.stepUpWithPassword(password)
        settle(true)
      }),
    [client, run, settle]
  )

  // Sends an email/SMS code (TOTP needs none). Some methods step up at once.
  const sendCode = useCallback(
    (method?: string) =>
      run(async () => {
        const out = await client.stepUpWithTwoFactor({ method })
        if (out.kind === "stepped_up") return settle(true)
        setState((s) => ({
          step: "code_sent",
          challenge: challengeOf(s),
          method: out.method,
          verificationId: out.verificationId,
        }))
      }),
    [client, run, settle]
  )

  const withTwoFactor = useCallback(
    (code: string, opts: { method?: string; backupCode?: boolean } = {}) =>
      run(async () => {
        const out = await client.stepUpWithTwoFactor({
          code,
          method: opts.backupCode
            ? undefined
            : (opts.method ??
              (state.step === "code_sent" ? state.method : undefined)),
          backupCode: opts.backupCode,
        })
        if (out.kind === "stepped_up") return settle(true)
        setState((s) => ({
          step: "code_sent",
          challenge: challengeOf(s),
          method: out.method,
          verificationId: out.verificationId,
        }))
      }),
    [client, run, settle, state]
  )

  // Leaves the page; AuthKit returns to returnTo?step_up=success|failed
  // (readStepUpReturn). Pending actions are not retried across the redirect.
  const withProvider = useCallback(
    (provider: string, returnTo: string) =>
      run(async () => {
        const url = await client.startOidcStepUp(provider, returnTo)
        ;(navigate.current ?? ((u: string) => window.location.assign(u)))(url)
      }),
    [client, run]
  )

  const cancel = useCallback(() => {
    clearError()
    settle(false)
  }, [clearError, settle])

  return {
    state,
    busy,
    error,
    guard,
    open,
    withPassword,
    sendCode,
    withTwoFactor,
    withProvider,
    cancel,
  }
}

export type StepUpController = ReturnType<typeof useStepUp>
