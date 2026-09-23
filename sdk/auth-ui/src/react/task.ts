import { useCallback, useRef, useState } from "react"

import { AuthKitError, AuthSessionChangedError } from "../client/errors.ts"

// Hook errors are always AuthKitError so hosts translate one thing: `code`.
// Local failures use "session_changed", "step_up_cancelled", "network_error"
// and "unknown_error".
export function toAuthKitError(error: unknown): AuthKitError {
  if (error instanceof AuthKitError) return error
  const local = (code: string, message: string) =>
    new AuthKitError(0, { type: "local", code, message })
  if (error instanceof AuthSessionChangedError)
    return local("session_changed", error.message)
  if (error instanceof TypeError) return local("network_error", error.message)
  return local(
    "unknown_error",
    error instanceof Error ? error.message : String(error)
  )
}

export const isStepUpCancelled = (error: unknown) =>
  error instanceof AuthKitError && error.code === "step_up_cancelled"

// Wraps a sensitive call; useStepUp().guard fits.
export type Guard = <T>(action: () => Promise<T>) => Promise<T>
export const unguarded: Guard = (action) => action()

// Single-flight async runner: busy/error state, errors normalized, never throws.
export function useTask() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<AuthKitError | null>(null)
  const inflight = useRef(false)

  const run = useCallback(
    async <T>(fn: () => Promise<T>): Promise<T | undefined> => {
      if (inflight.current) return undefined
      inflight.current = true
      setBusy(true)
      setError(null)
      try {
        return await fn()
      } catch (err) {
        if (!isStepUpCancelled(err)) setError(toAuthKitError(err))
        return undefined
      } finally {
        inflight.current = false
        setBusy(false)
      }
    },
    []
  )

  const clearError = useCallback(() => setError(null), [])
  return { busy, error, run, clearError }
}
