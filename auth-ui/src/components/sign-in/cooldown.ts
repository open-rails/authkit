import { useEffect, useState } from "react"

import { statedWait, type AuthKitError } from "#authui/client/errors"

// Counts down after each send so codes aren't requested in a burst. A rate
// limit's refusal states how long is left, and the countdown follows it.
export function useCooldown(
  seconds: number,
  startActive = false,
  refusal?: unknown
) {
  const [until, setUntil] = useState(() =>
    startActive ? Date.now() + seconds * 1000 : 0
  )
  const [now, setNow] = useState(() => Date.now())
  const wait = statedWait(refusal)
  const refusedAt = wait === undefined ? 0 : (refusal as AuthKitError).at
  const end = Math.max(until, refusedAt + (wait ?? 0) * 1000)
  const clock = Math.max(now, refusedAt)
  useEffect(() => {
    if (end <= clock) return
    const id = setTimeout(() => setNow(Date.now()), 250)
    return () => clearTimeout(id)
  }, [end, clock])
  const left = Math.max(0, Math.ceil((end - clock) / 1000))
  return {
    left,
    start: () => {
      const t = Date.now()
      setNow(t)
      setUntil(t + seconds * 1000)
    },
  }
}

// AuthKit answers code_expired once a sent code is gone (the 5th miss,
// expiry, or already used); a plain miss stays invalid_code and retryable.
export function useSpentCode(error: { code: string } | null | undefined) {
  const [renewed, setRenewed] = useState<unknown>(null)
  return {
    spent: error?.code === "code_expired" && error !== renewed,
    // Call when a new code is sent.
    renew: () => setRenewed(error),
  }
}
