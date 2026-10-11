import { useCallback, useEffect, useRef, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import {
  isStepUpCancelled,
  toAuthKitError,
  type StepUpResume,
} from "../react/task.ts"
import { useAdmin } from "./context.ts"

// Runs writes through the host's guard: busy, the last error, and a
// resume a step-up that leaves the page replays.
export function useWrite() {
  const { guard } = useAdmin()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<AuthKitError | null>(null)
  const run = useCallback(
    async <T>(
      action: () => Promise<T>,
      resume?: StepUpResume
    ): Promise<T | undefined> => {
      setBusy(true)
      setError(null)
      try {
        return await (guard ? guard(action, { resume }) : action())
      } catch (err) {
        if (!isStepUpCancelled(err)) setError(toAuthKitError(err))
        return undefined
      } finally {
        setBusy(false)
      }
    },
    [guard]
  )
  const clear = useCallback(() => setError(null), [])
  return { busy, error, run, clear }
}

// Registers what replays an action of kind once a step-up that left the
// page returns.
export function useResumer(kind: string, resumer: (data: unknown) => unknown) {
  const { guard } = useAdmin()
  const fn = useRef(resumer)
  useEffect(() => {
    fn.current = resumer
  })
  useEffect(
    () => guard?.onResume?.(kind, (data) => fn.current(data)),
    [guard, kind]
  )
}
