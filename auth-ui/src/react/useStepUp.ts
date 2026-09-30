import { useCallback, useEffect, useRef, useState } from "react"

import { AuthKitError } from "../client/errors.ts"
import { readStepUpRequired } from "../client/stepUp.ts"
import type { StepUpChallenge } from "../client/stepUp.ts"
import { useAuthClient } from "./context.ts"
import { useTask, type Guard } from "./task.ts"

export type StepUpState =
  | { step: "idle" }
  | { step: "required"; challenge: StepUpChallenge }
  | {
      step: "code_sent"
      challenge: StepUpChallenge
      // The factor the code went to; "" for the default one.
      factorId: string
      // Its masked address, when AuthKit listed it.
      destination: string | null
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
  s.step === "idle" ? { methods: ["2fa"], factors: [] } : s.challenge

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

  // Sends an email/SMS code to a factor, the default one when factorId is
  // omitted (TOTP needs none).
  const sendCode = useCallback(
    (factorId?: string) =>
      run(async () => {
        await client.sendStepUpCode({ factorId })
        setState((s) => {
          const challenge = challengeOf(s)
          const factor = challenge.factors.find((f) =>
            factorId ? f.id === factorId : f.is_default
          )
          return {
            step: "code_sent",
            challenge,
            factorId: factorId ?? "",
            destination: factor?.destination ?? null,
          }
        })
      }),
    [client, run]
  )

  const withTwoFactor = useCallback(
    (code: string, opts: { factorId?: string; backupCode?: boolean } = {}) =>
      run(async () => {
        await client.stepUpWithTwoFactor({
          code,
          factorId: opts.backupCode
            ? undefined
            : (opts.factorId ??
              (state.step === "code_sent" && state.factorId
                ? state.factorId
                : undefined)),
          backupCode: opts.backupCode,
        })
        settle(true)
      }),
    [client, run, settle, state]
  )

  // Leaves the page; AuthKit returns to returnTo#code= (the StepUpProvider
  // finishes it with client.completeStepUp). Pending actions are not
  // retried across the redirect.
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
