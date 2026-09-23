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
