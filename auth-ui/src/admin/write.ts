import { useCallback, useEffect, useRef, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import { isStepUpCancelled, toAuthKitError } from "../react/task.ts"
import { useAdmin } from "./context.ts"

type Actions = Record<string, (data: never) => Promise<unknown>>

type Done<A extends Actions> = <K extends keyof A>(
  kind: K,
  result: Awaited<ReturnType<A[K]>>,
  data: Parameters<A[K]>[0]
) => void

// A component's writes, each run through the host's guard with a resume, so
// a step-up that leaves the page replays it on return: busy, the last
// error, and done for what follows a write that landed.
export function useActions<A extends Actions>(
  scope: string,
  actions: A,
  done: Done<A>
) {
  const { guard } = useAdmin()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<AuthKitError | null>(null)
  const latest = useRef({ actions, done })
  useEffect(() => {
    latest.current = { actions, done }
  })
  const kindOf = useCallback((kind: string) => `${kind}:${scope}`, [scope])

  useEffect(() => {
    const on = guard?.onResume
    if (!on) return
    const offs = Object.keys(latest.current.actions).map((kind) =>
      on(kindOf(kind), async (data) => {
        const { actions, done } = latest.current
        try {
          const result = await actions[kind](data as never)
          done(kind, result as never, data as never)
        } catch (err) {
          setError(toAuthKitError(err))
        }
      })
    )
    return () => offs.forEach((off) => off())
  }, [guard, kindOf])

  const run = useCallback(
    async <K extends keyof A & string>(
      kind: K,
      data: Parameters<A[K]>[0]
    ): Promise<boolean> => {
      const { actions } = latest.current
      const action = () => actions[kind](data as never)
      setBusy(true)
      setError(null)
      try {
        const result = await (guard
          ? guard(action, { resume: { kind: kindOf(kind), data } })
          : action())
        latest.current.done(kind, result as never, data)
        return true
      } catch (err) {
        if (!isStepUpCancelled(err)) setError(toAuthKitError(err))
        return false
      } finally {
        setBusy(false)
      }
    },
    [guard, kindOf]
  )
  const clear = useCallback(() => setError(null), [])
  return { busy, error, run, clear }
}
