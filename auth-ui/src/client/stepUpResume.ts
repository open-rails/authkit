// A guarded action kept across a step-up that leaves the page: stored in
// sessionStorage with the actor, a nonce the return URL carries and a
// 15-minute lifetime, and replayed at most once.

export type PendingStepUpAction = { kind: string; data: unknown }

// The return URL's query parameter carrying the nonce.
export const STEP_UP_RESUME_PARAM = "authkit_step_up"

const KEY = "authkit:step-up:pending"
const LIFETIME_MS = 15 * 60 * 1000

type Stored = {
  actor: string
  nonce: string
  createdAt: number
  kind: string
  data: unknown
}

const store = (): Storage | null => {
  try {
    return typeof sessionStorage === "undefined" ? null : sessionStorage
  } catch {
    return null
  }
}

// Keeps action for actor; the nonce, or null when the browser keeps nothing.
export function storeStepUpAction(
  actor: string,
  action: PendingStepUpAction
): string | null {
  const nonce = crypto.randomUUID()
  const record: Stored = { actor, nonce, createdAt: Date.now(), ...action }
  try {
    const s = store()
    if (!s) return null
    s.setItem(KEY, JSON.stringify(record))
    return nonce
  } catch {
    return null
  }
}

// The stored action, once, when actor, nonce and lifetime all match; any
// other record is dropped.
export function takeStepUpAction(
  actor: string,
  nonce: string
): PendingStepUpAction | null {
  try {
    const s = store()
    const raw = s?.getItem(KEY)
    s?.removeItem(KEY)
    if (!raw) return null
    const r = JSON.parse(raw) as Partial<Stored>
    const age = Date.now() - (typeof r.createdAt === "number" ? r.createdAt : 0)
    if (
      r.actor !== actor ||
      r.nonce !== nonce ||
      typeof r.kind !== "string" ||
      age < 0 ||
      age > LIFETIME_MS
    )
      return null
    return { kind: r.kind, data: r.data }
  } catch {
    return null
  }
}

export function dropStepUpAction() {
  try {
    store()?.removeItem(KEY)
  } catch {
    // best effort
  }
}

// returnTo with the nonce in its query.
export function withResumeNonce(returnTo: string, nonce: string): string {
  const url = new URL(
    returnTo,
    globalThis.location?.origin ?? "http://localhost"
  )
  url.searchParams.set(STEP_UP_RESUME_PARAM, nonce)
  return `${url.pathname}${url.search}${url.hash}`
}

let returned: string | null | undefined

// The nonce this page load returned with, read once and removed from the
// address bar (history state kept, so a host router's entry survives).
export function takeReturnNonce(): string | null {
  if (returned !== undefined) return returned
  returned = null
  if (typeof window === "undefined") return null
  const url = new URL(window.location.href)
  const nonce = url.searchParams.get(STEP_UP_RESUME_PARAM)
  if (!nonce) return null
  returned = nonce
  url.searchParams.delete(STEP_UP_RESUME_PARAM)
  window.history.replaceState(
    window.history.state,
    "",
    `${url.pathname}${url.search}${url.hash}`
  )
  return nonce
}

export function consumeReturnNonce() {
  returned = null
}
