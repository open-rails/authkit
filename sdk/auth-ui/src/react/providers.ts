import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import type { AuthClient, RedirectResult } from "../client/client.ts"
import type { LoginContinuation } from "../client/continuation.ts"
import { AuthKitError } from "../client/errors.ts"
import type { GuardOptions } from "./account.ts"
import { useAuthClient, useCapabilities, useUser } from "./context.ts"
import { toAuthKitError, unguarded, useTask } from "./task.ts"

export type ContactVerificationState =
  | { step: "idle" }
  | { step: "code_sent"; identifier: string }
  | { step: "done"; identifier: string }

// Change (or re-verify) the signed-in user's email or phone: a code goes to
// the new address, confirming it switches the contact.
export function useContactVerification(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { refetch } = useUser()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<ContactVerificationState>({
    step: "idle",
  })

  // `password` satisfies the fresh-auth gate without a separate step-up.
  const request = useCallback(
    (identifier: string, opts: { password?: string } = {}) =>
      run(async () => {
        const id = identifier.trim()
        await guard(() =>
          client.requestVerification({
            identifier: id,
            password: opts.password,
          })
        )
        setState({ step: "code_sent", identifier: id })
      }),
    [client, guard, run]
  )

  const resend = useCallback(
    () =>
      run(async () => {
        if (state.step !== "code_sent") return
        const { identifier } = state
        await guard(() => client.requestVerification({ identifier }))
      }),
    [client, guard, run, state]
  )

  const confirm = useCallback(
    (code: string) =>
      run(async () => {
        if (state.step !== "code_sent") return
        await client.confirmVerification({
          identifier: state.identifier,
          code: code.trim(),
        })
        setState({ step: "done", identifier: state.identifier })
        void refetch()
      }),
    [client, run, state, refetch]
  )

  const reset = useCallback(() => {
    clearError()
    setState({ step: "idle" })
  }, [clearError])

  return { state, busy, error, request, resend, confirm, reset }
}

export type LinkedProvider = {
  id: string
  name: string
  linked: boolean
  supportsLink: boolean
  supportsLogin: boolean
}

export type LinkedProvidersOptions = GuardOptions & {
  // Where provider linking sends the browser. Default location.assign.
  navigate?: (url: string) => void
}

// External login providers from /capabilities, joined with the user's links.
export function useLinkedProviders(options: LinkedProvidersOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { capabilities, loading: capsLoading } = useCapabilities()
  const { user, loading: userLoading, refetch } = useUser()
  const { busy, error, run } = useTask()
  const navigate = useRef(options.navigate)
  useEffect(() => {
    navigate.current = options.navigate
  })

  const providers: LinkedProvider[] = useMemo(() => {
    const linked = new Set(user?.linked_providers ?? [])
    return (capabilities?.external_login_providers ?? []).map((p) => ({
      id: p.id,
      name: p.name,
      linked: linked.has(p.id),
      supportsLink: p.supports_link,
      supportsLogin: p.supports_login,
    }))
  }, [capabilities, user])

  // Leaves the page; the return lands as #flow=link (useOidcCallback).
  const link = useCallback(
    (provider: string) =>
      run(async () => {
        const url = await guard(() => client.startProviderLink(provider))
        ;(navigate.current ?? ((u: string) => window.location.assign(u)))(url)
      }),
    [client, guard, run]
  )

  const unlink = useCallback(
    (provider: string, opts: { password?: string } = {}) =>
      run(async () => {
        await guard(() => client.unlinkProvider(provider, opts))
        await refetch()
      }),
    [client, guard, run, refetch]
  )

  return {
    providers,
    loading: capsLoading || userLoading,
    busy,
    error,
    link,
    unlink,
  }
}

// Callback route: consumes AuthKit's redirect fragment once (StrictMode-safe).
// result is undefined while pending, null when the URL carried none.
export function useOidcCallback(
  options: { onResult?: (result: RedirectResult | null) => void } = {}
) {
  const client = useAuthClient()
  const [state, setState] = useState<{
    result?: RedirectResult | null
    error: AuthKitError | null
  }>({ error: null })
  const consumed = useRef<typeof state | null>(null)
  const onResult = useRef(options.onResult)
  useEffect(() => {
    onResult.current = options.onResult
  })

  useEffect(() => {
    if (!consumed.current) {
      try {
        consumed.current = { result: client.completeRedirect(), error: null }
        onResult.current?.(consumed.current.result ?? null)
      } catch (err) {
        consumed.current = { result: null, error: toAuthKitError(err) }
      }
    }
    setState(consumed.current)
  }, [client])

  return state
}

export type VerifyLinkState =
  | { status: "pending" }
  | { status: "verified"; signedIn: boolean; returnTo?: string }
  | { status: "continuation"; continuation: LoginContinuation }
  | { status: "error"; error: AuthKitError }

// One confirmation per client and token. The confirm itself changes the
// session, so hosts that remount per session would otherwise resend a
// single-use token and report it as expired.
const linkConfirmations = new WeakMap<
  AuthClient,
  Map<string, Promise<VerifyLinkState>>
>()

function confirmLink(client: AuthClient, token: string) {
  let byToken = linkConfirmations.get(client)
  if (!byToken) linkConfirmations.set(client, (byToken = new Map()))
  let result = byToken.get(token)
  if (!result) {
    result = client.confirmVerification({ token }).then(
      (out): VerifyLinkState =>
        out.kind === "session"
          ? { status: "verified", signedIn: true, returnTo: out.returnTo }
          : out.kind === "contact_changed"
            ? { status: "verified", signedIn: false }
            : { status: "continuation", continuation: out },
      (err: unknown): VerifyLinkState => ({
        status: "error",
        error: toAuthKitError(err),
      })
    )
    byToken.set(token, result)
  }
  return result
}

// Verification link route: confirms the link token once per client, across
// StrictMode and remounts. "verified" with signedIn when AuthKit also opened
// a session.
export function useVerifyLink(
  token: string | null | undefined
): VerifyLinkState {
  const client = useAuthClient()
  const [state, setState] = useState<{
    token: string
    value: VerifyLinkState
  } | null>(null)

  useEffect(() => {
    if (!token) return
    let live = true
    void confirmLink(client, token).then((value) => {
      if (live) setState({ token, value })
    })
    return () => {
      live = false
    }
  }, [client, token])

  if (!token)
    return {
      status: "error",
      error: new AuthKitError(0, {
        type: "local",
        code: "invalid_or_expired_token",
        message: "verification link has no token",
      }),
    }
  return state?.token === token ? state.value : { status: "pending" }
}
