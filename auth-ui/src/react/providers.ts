import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import type { PendingSignIn } from "../client/authResult.ts"
import type { AuthClient, RedirectResult } from "../client/client.ts"
import { AuthKitError } from "../client/errors.ts"
import type { FreshAuth } from "../client/types.ts"
import type { GuardOptions } from "./account.ts"
import { useAuthClient, useCapabilities, useUser } from "./context.ts"
import { toAuthKitError, unguarded, useTask } from "./task.ts"

export type ContactVerificationState =
  | { step: "idle" }
  // change: the code confirms a new address for the account.
  | { step: "code_sent"; identifier: string; change?: "email" | "phone" }
  | { step: "done"; identifier: string }

// Proves an address with a one-time code: one already on the account
// (request), or a new email or phone for it (change, which needs a recent
// sign-in).
export function useContactVerification(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { refetch } = useUser()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<ContactVerificationState>({
    step: "idle",
  })

  const request = useCallback(
    (identifier: string) =>
      run(async () => {
        const id = identifier.trim()
        await client.requestVerification({ identifier: id })
        setState({ step: "code_sent", identifier: id })
      }),
    [client, run]
  )

  const sendChange = useCallback(
    (change: "email" | "phone", identifier: string) =>
      guard(() =>
        change === "email"
          ? client.changeEmail(identifier)
          : client.changePhone(identifier)
      ),
    [client, guard]
  )

  const change = useCallback(
    (input: { email: string } | { phoneNumber: string }) =>
      run(async () => {
        const [kind, value] =
          "email" in input
            ? (["email", input.email.trim()] as const)
            : (["phone", input.phoneNumber.trim()] as const)
        await sendChange(kind, value)
        setState({ step: "code_sent", identifier: value, change: kind })
      }),
    [run, sendChange]
  )

  const resend = useCallback(
    () =>
      run(async () => {
        if (state.step !== "code_sent") return
        const { identifier, change } = state
        if (change) await sendChange(change, identifier)
        else await client.requestVerification({ identifier })
      }),
    [client, run, sendChange, state]
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

  const removePhone = useCallback(
    () =>
      run(async () => {
        await guard(() => client.removePhone())
        void refetch()
      }),
    [client, guard, run, refetch]
  )

  const reset = useCallback(() => {
    clearError()
    setState({ step: "idle" })
  }, [clearError])

  return {
    state,
    busy,
    error,
    request,
    change,
    resend,
    confirm,
    removePhone,
    reset,
  }
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
    const linked = new Set(user?.providers.map((p) => p.provider) ?? [])
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
    (provider: string) =>
      run(async () => {
        await guard(() => client.unlinkProvider(provider))
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

type Settled<T> = { result: T | null; error: AuthKitError | null }

// A page load's OIDC result, consumed once per client: the exchange changes
// the session, and a host that remounts per session must not consume the
// (scrubbed) fragment again.
function once<T>(
  memo: WeakMap<AuthClient, Promise<Settled<T>>>,
  client: AuthClient,
  consume: () => Promise<T | null>
): Promise<Settled<T>> {
  let settled = memo.get(client)
  if (!settled) {
    settled = consume().then(
      (result) => ({ result, error: null }),
      (err: unknown) => ({ result: null, error: toAuthKitError(err) })
    )
    memo.set(client, settled)
  }
  return settled
}

// Subscribes the live mount to a once() result.
function useSettled<T>(
  load: () => Promise<Settled<T>>,
  onSettled?: (settled: Settled<T>) => void
) {
  const [state, setState] = useState<Settled<T> | null>(null)
  const latest = useRef(onSettled)
  useEffect(() => {
    latest.current = onSettled
  })
  useEffect(() => {
    let live = true
    void load().then((settled) => {
      if (!live) return
      setState(settled)
      latest.current?.(settled)
    })
    return () => {
      live = false
    }
  }, [load])
  return state
}

const redirects = new WeakMap<AuthClient, Promise<Settled<RedirectResult>>>()

// Callback route: trades AuthKit's redirect fragment for its result once.
// result is undefined while pending, null when the URL carried none.
export function useOidcCallback(
  options: { onResult?: (result: RedirectResult | null) => void } = {}
) {
  const client = useAuthClient()
  const onResult = options.onResult
  const load = useCallback(
    () => once(redirects, client, () => client.completeRedirect()),
    [client]
  )
  const state = useSettled(load, (s) => {
    if (!s.error) onResult?.(s.result)
  })
  return state
    ? { result: state.result, error: state.error }
    : { result: undefined, error: null }
}

const stepUps = new WeakMap<AuthClient, Promise<Settled<FreshAuth>>>()

// A page an OIDC step-up returned to (`#code=` / `#error=`): adopts the
// re-authenticated session once. freshAuth is null when there was none.
export function useStepUpReturn(): {
  pending: boolean
  freshAuth: FreshAuth | null
  error: AuthKitError | null
} {
  const client = useAuthClient()
  const load = useCallback(
    () => once(stepUps, client, () => client.completeStepUp()),
    [client]
  )
  const state = useSettled(load)
  return {
    pending: !state,
    freshAuth: state?.result ?? null,
    error: state?.error ?? null,
  }
}

export type VerifyLinkState =
  | { status: "pending" }
  | { status: "verified"; signedIn: boolean; returnTo?: string }
  | { status: "continuation"; continuation: PendingSignIn }
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
        !out
          ? { status: "verified", signedIn: false }
          : out.status === "complete"
            ? {
                status: "verified",
                signedIn: true,
                returnTo: out.return_to ?? undefined,
              }
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
        code: "invalid_link",
        message: "verification link has no token",
      }),
    }
  return state?.token === token ? state.value : { status: "pending" }
}
