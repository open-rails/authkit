// AuthKit's popup result: a one-time `code` for POST /oidc/exchange, or an
// `error` code. It never carries a token.
// How long a closed popup's already-posted answer has to arrive before the
// wait reports the window as closed.
export const POPUP_CLOSE_GRACE_MS = 1_000

export type PopupMessage = {
  type: "AUTHKIT_OIDC_RESULT" | "AUTHKIT_OIDC_ERROR"
  nonce: string
  provider?: string
  code?: string
  error?: string
}

export type PopupWait =
  | { ok: true; message: PopupMessage }
  | { ok: false; reason: "blocked" | "closed" | "timeout" }
  | { ok: false; reason: "start_failed"; error: unknown }

type Options = {
  nonce: string
  allowedOrigins: ReadonlySet<string>
  timeoutMs: number
}

export function randomNonce(bytes = 16): string {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

function centeredFeatures(width: number, height: number): string {
  const w = window.outerWidth || window.innerWidth || width
  const h = window.outerHeight || window.innerHeight || height
  const left = (window.screenX ?? 0) + (w - width) / 2
  const top = (window.screenY ?? 0) + (h - height) / 2
  return `popup=yes,width=${width},height=${height},left=${left},top=${top}`
}

// Opens the window synchronously (call from a user gesture) and waits for
// AuthKit's postMessage from that exact window carrying our nonce. A target
// resolved asynchronously loads into the already-open window.
export function waitForPopup(
  target: string | (() => Promise<string>),
  opts: Options
): Promise<PopupWait> {
  const popup = window.open(
    typeof target === "string" ? target : "about:blank",
    "authkit_oidc",
    centeredFeatures(520, 640)
  )
  if (!popup) return Promise.resolve({ ok: false, reason: "blocked" })
  return new Promise((resolve) => {
    let closing: ReturnType<typeof setTimeout> | undefined
    const finish = (result: PopupWait) => {
      clearTimeout(timer)
      clearInterval(poll)
      clearTimeout(closing)
      window.removeEventListener("message", onMessage)
      try {
        popup.close()
      } catch {
        // already gone
      }
      resolve(result)
    }
    const onMessage = (ev: MessageEvent) => {
      if (ev.source !== popup || !opts.allowedOrigins.has(ev.origin)) return
      const data = ev.data as Record<string, unknown> | null
      if (
        data?.type !== "AUTHKIT_OIDC_RESULT" &&
        data?.type !== "AUTHKIT_OIDC_ERROR"
      )
        return
      if (data.nonce !== opts.nonce) return
      finish({ ok: true, message: data as unknown as PopupMessage })
    }
    const timer = setTimeout(
      () => finish({ ok: false, reason: "timeout" }),
      opts.timeoutMs
    )
    // AuthKit's result page posts and then closes itself, so a closed popup
    // may still have its result queued for this window.
    const poll = setInterval(() => {
      if (!popup.closed) return
      clearInterval(poll)
      closing = setTimeout(
        () => finish({ ok: false, reason: "closed" }),
        POPUP_CLOSE_GRACE_MS
      )
    }, 500)
    window.addEventListener("message", onMessage)
    if (typeof target !== "string") {
      target().then(
        (url) => {
          if (!popup.closed) popup.location.href = url
        },
        (error: unknown) => finish({ ok: false, reason: "start_failed", error })
      )
    }
  })
}
