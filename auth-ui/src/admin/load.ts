import { useCallback, useEffect, useRef, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import { toAuthKitError } from "../react/task.ts"

export type Loaded<T> = {
  data: T | undefined
  error: AuthKitError | null
  loading: boolean
  reload(): void
}

// Loads while key is set, again when it changes or on reload; a stale
// answer is dropped.
export function useLoad<T>(
  key: string | null,
  load: (signal: AbortSignal) => Promise<T>
): Loaded<T> {
  const [state, setState] = useState<{
    key: string
    data?: T
    error: AuthKitError | null
  } | null>(null)
  const [nonce, setNonce] = useState(0)
  const fn = useRef(load)
  useEffect(() => {
    fn.current = load
  })
  useEffect(() => {
    if (key === null) return
    const ctl = new AbortController()
    fn.current(ctl.signal).then(
      (data) => !ctl.signal.aborted && setState({ key, data, error: null }),
      (err: unknown) =>
        !ctl.signal.aborted &&
        setState((s) => ({
          key,
          data: s?.key === key ? s.data : undefined,
          error: toAuthKitError(err),
        }))
    )
    return () => ctl.abort()
  }, [key, nonce])
  const reload = useCallback(() => setNonce((n) => n + 1), [])
  const current = key !== null && state?.key === key ? state : null
  return {
    data: current?.data,
    error: current?.error ?? null,
    loading: key !== null && (!current || (!current.data && !current.error)),
    reload,
  }
}
