import { useEffect, useState } from "react"

// Counts down after each send so codes aren't requested in a burst.
export function useCooldown(seconds: number, startActive = false) {
  const [until, setUntil] = useState(() =>
    startActive ? Date.now() + seconds * 1000 : 0
  )
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (until <= now) return
    const id = setTimeout(() => setNow(Date.now()), 250)
    return () => clearTimeout(id)
  }, [until, now])
  const left = Math.max(0, Math.ceil((until - now) / 1000))
  return {
    left,
    start: () => {
      const t = Date.now()
      setNow(t)
      setUntil(t + seconds * 1000)
    },
  }
}

// AuthKit answers 2fa_code_expired once a sent code is gone (the 5th miss,
// expiry, or already used); a plain miss stays invalid_code and retryable.
export function useSpentCode(error: { code: string } | null | undefined) {
  const [renewed, setRenewed] = useState<unknown>(null)
  return {
    spent: error?.code === "2fa_code_expired" && error !== renewed,
    // Call when a new code is sent.
    renew: () => setRenewed(error),
  }
}
