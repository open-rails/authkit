import { useCallback, useEffect, useRef, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import type { UserSession } from "../client/types.ts"
import { useAuthClient, useSession } from "./context.ts"
import { toAuthKitError, unguarded, useTask, type Guard } from "./task.ts"

// Sensitive account hooks take `guard` (useStepUp().guard) to step up and retry.
export type GuardOptions = { guard?: Guard }

export type PasswordResetState =
  | { step: "request" }
  | { step: "sent"; identifier: string }
  | { step: "confirm" }
  | { step: "done" }

// Pass the link token (readLinkFragment(location.hash)?.token) to start at "confirm".
export function usePasswordReset(options: { token?: string } = {}) {
  const client = useAuthClient()
  const { busy, error, run, clearError } = useTask()
  const [state, setState] = useState<PasswordResetState>(
    options.token ? { step: "confirm" } : { step: "request" }
  )

  // Always succeeds for a well-formed identifier (anti-enumeration).
  const request = useCallback(
    (identifier: string) =>
      run(async () => {
        await client.requestPasswordReset(identifier.trim())
        setState({ step: "sent", identifier: identifier.trim() })
      }),
    [client, run]
  )

  const confirm = useCallback(
    (input: { newPassword: string; token?: string }) =>
      run(async () => {
        const token = input.token ?? options.token
        if (!token) throw new Error("password reset token is missing")
        await client.confirmPasswordReset({
          token,
          newPassword: input.newPassword,
        })
        setState({ step: "done" })
      }),
    [client, run, options.token]
  )

  const reset = useCallback(() => {
    clearError()
    setState({ step: "request" })
  }, [clearError])

  return { state, busy, error, request, confirm, reset }
}

export function useChangePassword(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { busy, error, run, clearError } = useTask()
  const [done, setDone] = useState(false)

  // Without currentPassword AuthKit demands a fresh session (step-up).
  const changePassword = useCallback(
    (input: { currentPassword?: string; newPassword: string }) =>
      run(async () => {
        setDone(false)
        await guard(() => client.changePassword(input))
        setDone(true)
      }),
    [client, guard, run]
  )

  const reset = useCallback(() => {
    clearError()
    setDone(false)
  }, [clearError])

  return {
    state: done ? ("done" as const) : ("idle" as const),
    busy,
    error,
    changePassword,
    reset,
  }
}

export function useDeleteAccount(
  options: GuardOptions & { onDeleted?: () => void } = {}
) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const { busy, error, run } = useTask()
  const [deleted, setDeleted] = useState(false)
  const onDeleted = useRef(options.onDeleted)
  useEffect(() => {
    onDeleted.current = options.onDeleted
  })

  // Soft delete; the session ends (often unmounting the caller, hence
  // onDeleted). Signing in later offers recovery.
  const deleteAccount = useCallback(
    (input: { password?: string } = {}) =>
      run(async () => {
        await guard(() => client.deleteAccount(input))
        setDeleted(true)
        onDeleted.current?.()
      }),
    [client, guard, run]
  )

  return {
    state: deleted ? ("deleted" as const) : ("idle" as const),
    busy,
    error,
    deleteAccount,
  }
}

export type SessionEntry = UserSession & { current: boolean }

export function useSessions(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const session = useSession()
  const sid =
    session.status === "authenticated" ? String(session.claims.sid ?? "") : null
  const { busy, error, run } = useTask()
  const [nonce, setNonce] = useState(0)
  const request = `${sid}|${nonce}`
  const [listed, setListed] = useState<{
    request: string
    data: UserSession[] | null
    error: AuthKitError | null
  } | null>(null)

  useEffect(() => {
    if (sid === null) return
    const ctl = new AbortController()
    client.listSessions(ctl.signal).then(
      (data) => setListed({ request, data, error: null }),
      (err: unknown) => {
        if (!ctl.signal.aborted)
          setListed({ request, data: null, error: toAuthKitError(err) })
      }
    )
    return () => ctl.abort()
  }, [client, sid, request])

  const refetch = useCallback(() => setNonce((n) => n + 1), [])

  // Batch-first: pass one id or many.
  const revoke = useCallback(
    (sessionIds: readonly string[]) =>
      run(async () => {
        await guard(() => client.revokeSessions(sessionIds))
        setListed((l) =>
          l?.data
            ? {
                ...l,
                data: l.data.filter((s) => !sessionIds.includes(s.session_id)),
              }
            : l
        )
      }),
    [client, guard, run]
  )

  // Every session including this one: the user is signed out.
  const revokeAll = useCallback(
    () => run(() => guard(() => client.revokeAllSessions())),
    [client, guard, run]
  )

  // Keep the previous list while a refetch for the same session runs.
  const usable =
    sid !== null && listed?.request.startsWith(`${sid}|`) ? listed : null
  const sessions: SessionEntry[] | null =
    usable?.data?.map((s) => ({
      ...s,
      current: !!sid && s.session_id === sid,
    })) ?? null

  return {
    sessions,
    loading: sid !== null && listed?.request !== request,
    busy,
    // Action error first, then the listing error.
    error: error ?? usable?.error ?? null,
    refetch,
    revoke,
    revokeAll,
  }
}
