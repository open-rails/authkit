import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import { AuthKitError } from "../client/errors.ts"
import { readStepUpRequired } from "../client/stepUp.ts"
import type { StepUpChallenge } from "../client/stepUp.ts"
import { storeStepUpAction, withResumeNonce } from "../client/stepUpResume.ts"
import { passkeyDismissed } from "../client/webauthn.ts"
import {
  createSolanaAuth,
  isSolanaWalletError,
  type SolanaSigner,
} from "../solana/core.ts"
import { useAuthClient } from "./context.ts"
import {
  useTask,
  type Guard,
  type StepUpResume,
  type StepUpResumer,
} from "./task.ts"

// A proven address a step-up code can go to.
export type StepUpChannel = "email" | "sms"

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
  | {
      step: "contact_code_sent"
      challenge: StepUpChallenge
      channel: StepUpChannel
    }

export type StepUpOptions = {
  // Where OIDC step-up sends the browser. Default location.assign.
  navigate?: (url: string) => void
}

type Waiter = {
  action: () => Promise<unknown>
  resume?: StepUpResume
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

// The actions waiting on one step-up, and the resumers that replay an
// action a provider step-up returns with. guard is stable for the hook's
// life.
function createWaitingRoom(open: (challenge: StepUpChallenge) => void) {
  let waiters: Waiter[] = []
  const resumers = new Map<string, StepUpResumer>()
  // A returned action whose resumer is not registered yet.
  let parked: StepUpResume | null = null
  const replay = (action: StepUpResume, resumer: StepUpResumer) =>
    void Promise.resolve()
      .then(() => resumer(action.data))
      .catch(() => undefined)
  const guard: Guard = <T>(
    action: () => Promise<T>,
    options?: { resume?: StepUpResume }
  ) =>
    action().catch((err: unknown) => {
      const challenge = readStepUpRequired(err)
      if (!challenge) throw err
      return new Promise<T>((resolve, reject) => {
        waiters.push({
          action,
          resume: options?.resume,
          resolve: resolve as (value: unknown) => void,
          reject,
        })
        open(challenge)
      })
    })
  guard.onResume = (kind, resumer) => {
    resumers.set(kind, resumer)
    if (parked?.kind === kind) {
      const action = parked
      parked = null
      replay(action, resumer)
    }
    return () => {
      if (resumers.get(kind) === resumer) resumers.delete(kind)
    }
  }
  return {
    guard,
    wait(challenge: StepUpChallenge, resume?: StepUpResume): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        waiters.push({
          action: async () => undefined,
          resume,
          resolve: () => resolve(),
          reject,
        })
        open(challenge)
      })
    },
    take() {
      const pending = waiters
      waiters = []
      return pending
    },
    // The first waiting action a step-up that leaves the page keeps.
    resumable: () => waiters.find((w) => w.resume)?.resume,
    // Replays an action a provider step-up returned with, now or once its
    // resumer registers.
    returned(action: StepUpResume) {
      const resumer = resumers.get(action.kind)
      if (resumer) replay(action, resumer)
      else parked = action
    },
  }
}

export function useStepUp(options: StepUpOptions = {}) {
  const client = useAuthClient()
  const { busy, error, run, clearError } = useTask()
  const solana = useMemo(() => createSolanaAuth(client), [client])
  const [state, setState] = useState<StepUpState>({ step: "idle" })
  const [room] = useState(() =>
    createWaitingRoom((challenge) =>
      setState((s) => (s.step === "idle" ? { step: "required", challenge } : s))
    )
  )
  const navigate = useRef(options.navigate)
  useEffect(() => {
    navigate.current = options.navigate
  })

  const settle = useCallback(
    (ok: boolean) => {
      const pending = room.take()
      setState({ step: "idle" })
      for (const w of pending) {
        if (ok) w.action().then(w.resolve, w.reject)
        else w.reject(cancelled())
      }
    },
    [room]
  )

  useEffect(() => () => settle(false), [settle])

  // Runs a sensitive action; on 401 step_up_required it waits for the user to
  // step up, then retries. Rejects with code "step_up_cancelled" on cancel().
  // A resume is kept if the step-up leaves the page (withProvider).
  const guard = room.guard

  // Hands over the action a provider step-up returned with (StepUpProvider
  // calls it after checking the return).
  const resume = useCallback(
    (action: StepUpResume | null) => {
      if (action) room.returned(action)
    },
    [room]
  )

  // Proves identity before showing a sensitive editor, without submitting any
  // proposed new secret. Methods always come from the authenticated server.
  const authenticate = useCallback(
    async (options?: { resume?: StepUpResume }) => {
      const security = await client.getSecurity()
      await room.wait(
        {
          methods: security.step_up_methods,
          factors: security.two_factor.factors,
        },
        options?.resume
      )
    },
    [client, room]
  )

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

  // Sends a code to the account's proven email or phone.
  const sendContactCode = useCallback(
    (channel: StepUpChannel) =>
      run(async () => {
        await client.sendContactStepUpCode(channel)
        setState((s) => ({
          step: "contact_code_sent",
          challenge: challengeOf(s),
          channel,
        }))
      }),
    [client, run]
  )

  const withContactCode = useCallback(
    (code: string) =>
      run(async () => {
        await client.stepUpWithContactCode(code)
        settle(true)
      }),
    [client, run, settle]
  )

  // Asks the browser for one of the account's passkeys; call from a click.
  // Closing the browser's prompt leaves the dialog as it was.
  const withPasskey = useCallback(
    () =>
      run(async () => {
        try {
          await client.stepUpWithPasskey()
        } catch (err) {
          if (passkeyDismissed(err)) return
          throw err
        }
        settle(true)
      }),
    [client, run, settle]
  )

  // Signs a step-up challenge with the linked wallet that acquire resolves.
  // A dismissed wallet prompt leaves the dialog as it was.
  const withSolana = useCallback(
    (acquire: () => Promise<SolanaSigner>) =>
      run(async () => {
        try {
          await solana.stepUp(await acquire())
        } catch (err) {
          if (isSolanaWalletError(err) && err.reason === "rejected") return
          throw err
        }
        settle(true)
      }),
    [solana, run, settle]
  )

  // Leaves the page; AuthKit returns to returnTo#code= (the StepUpProvider
  // finishes it with client.completeStepUp). The first pending action with
  // a resume is kept for the return, its nonce in returnTo's query; the
  // others are not retried.
  const withProvider = useCallback(
    (provider: string, returnTo: string) =>
      run(async () => {
        const pending = room.resumable()
        const session = client.getSnapshot()
        const nonce =
          pending && session.status === "authenticated"
            ? storeStepUpAction(session.userId, pending)
            : null
        const url = await client.startOidcStepUp(
          provider,
          nonce ? withResumeNonce(returnTo, nonce) : returnTo
        )
        ;(navigate.current ?? ((u: string) => window.location.assign(u)))(url)
      }),
    [client, run, room]
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
    authenticate,
    open,
    withPassword,
    sendCode,
    withTwoFactor,
    sendContactCode,
    withContactCode,
    withPasskey,
    withSolana,
    withProvider,
    resume,
    cancel,
  }
}

export type StepUpController = ReturnType<typeof useStepUp>
