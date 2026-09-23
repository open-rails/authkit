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

// AuthKit keeps an emailed/texted code across wrong guesses and invalidates it
// on the 5th miss or after 10 minutes, answering the same error as a plain miss.
const MAX_MISSES = 5
const CODE_TTL_MS = 10 * 60_000
const MISS = new Set(["invalid_code", "invalid_or_expired_code"])

// Tracks one sent code: `spent` once AuthKit has surely invalidated it.
export function useCodeBudget(error: { code: string } | null | undefined) {
  const [misses, setMisses] = useState(0)
  const [seen, setSeen] = useState(error)
  const [sentAt, setSentAt] = useState(() => Date.now())
  const [expired, setExpired] = useState(false)
  if (error !== seen) {
    setSeen(error)
    if (error && MISS.has(error.code)) setMisses((n) => n + 1)
  }
  useEffect(() => {
    const id = setTimeout(
      () => setExpired(true),
      Math.max(0, sentAt + CODE_TTL_MS - Date.now())
    )
    return () => clearTimeout(id)
  }, [sentAt])
  return {
    spent: misses >= MAX_MISSES || (expired && misses > 0),
    // Call when a new code is sent.
    renew: () => {
      setMisses(0)
      setExpired(false)
      setSentAt(Date.now())
    },
  }
}
