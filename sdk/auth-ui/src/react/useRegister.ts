import { useCallback, useEffect, useRef, useState } from "react"

import type { LoginContinuation } from "../client/continuation.ts"
import type { Availability } from "../client/types.ts"
import { useAuthClient } from "./context.ts"
import { useTask } from "./task.ts"

export type RegisterState =
  | { step: "form" }
  | { step: "verify"; identifier: string; channel: "email" | "phone" }
  // Verification signed in but needs more (e.g. forced 2FA enrollment):
  // hand it to useLogin().resume.
  | { step: "continuation"; continuation: LoginContinuation }
  | { step: "done"; signedIn: boolean; returnTo?: string }

export type RegisterInput = {
  identifier: string
  username: string
  password: string
}

export type RegisterOptions = {
  accountInviteToken?: string
  onSignedIn?: (result: { returnTo?: string }) => void
}

export function useRegister(options: RegisterOptions = {}) {
  const client = useAuthClient()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<RegisterState>({ step: "form" })
  const [availability, setAvailability] = useState<Availability | null>(null)
  // abandon() proves ownership of the pending registration with its password.
  const pending = useRef<RegisterInput | null>(null)
  const lookup = useRef<AbortController | null>(null)
  const opts = useRef(options)
  useEffect(() => {
    opts.current = options
  })
  useEffect(() => () => lookup.current?.abort(), [])

  const done = useCallback((signedIn: boolean, returnTo?: string) => {
    pending.current = null
    setState({ step: "done", signedIn, returnTo })
    if (signedIn) opts.current.onSignedIn?.({ returnTo })
  }, [])

  // Latest call wins; debounce in the host. Null when superseded or failed.
  const checkAvailability = useCallback(
    async (input: {
      username?: string
      email?: string
      phoneNumber?: string
    }): Promise<Availability | null> => {
      lookup.current?.abort()
      const ctl = new AbortController()
      lookup.current = ctl
      try {
        const out = await client.checkAvailability(input, ctl.signal)
        if (ctl.signal.aborted) return null
        setAvailability(out)
        return out
      } catch {
        return null
      }
    },
    [client]
  )

  const register = useCallback(
    (input: RegisterInput) =>
      run(async () => {
        const out = await client.register({
          ...input,
          accountInviteToken: opts.current.accountInviteToken,
        })
        if (out.signedIn || out.next_action === "none")
          return done(out.signedIn)
        pending.current = input
        setState({
          step: "verify",
          identifier: input.identifier,
          channel: out.next_action === "verify_phone" ? "phone" : "email",
        })
      }),
    [client, run, done]
  )

  // A correct code verifies the contact and signs in.
  const verify = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "verify") return
        const out = await client.confirmVerification({
          identifier: state.identifier,
          code: code.trim(),
        })
        if (out.kind === "session") return done(true, out.returnTo)
        if (out.kind !== "contact_changed") {
          pending.current = null
          setState({ step: "continuation", continuation: out })
        }
      }),
    [client, run, done, state]
  )

  const resend = useCallback(
    () =>
      run(async () => {
        if (state.step === "verify")
          await client.resendRegistration(state.identifier)
      }),
    [client, run, state]
  )

  // Discards the pending registration so the identifier can be reused.
  const abandon = useCallback(
    () =>
      run(async () => {
        const p = pending.current
        if (state.step !== "verify" || !p) return
        await client.abandonRegistration({
          identifier: p.identifier,
          password: p.password,
        })
        pending.current = null
        setState({ step: "form" })
      }),
    [client, run, state]
  )

  const reset = useCallback(() => {
    pending.current = null
    clearError()
    setAvailability(null)
    setState({ step: "form" })
  }, [clearError])

  return {
    state,
    busy,
    error,
    availability,
    checkAvailability,
    register,
    verify,
    resend,
    abandon,
    reset,
  }
}
