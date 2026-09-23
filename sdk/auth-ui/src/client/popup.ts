export type PopupMessage = Record<string, unknown> & {
  type: "AUTHKIT_OIDC_RESULT" | "AUTHKIT_OIDC_ERROR"
}

export type PopupWait =
  | { ok: true; message: PopupMessage }
  | { ok: false; reason: "blocked" | "closed" | "timeout" }

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

// Opens url synchronously (call from a user gesture) and waits for AuthKit's
// postMessage from that exact window carrying our nonce.
export function waitForPopup(url: string, opts: Options): Promise<PopupWait> {
  const popup = window.open(url, "authkit_oidc", centeredFeatures(520, 640))
  if (!popup) return Promise.resolve({ ok: false, reason: "blocked" })
  return new Promise((resolve) => {
    const finish = (result: PopupWait) => {
      clearTimeout(timer)
      clearInterval(poll)
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
      finish({ ok: true, message: data as PopupMessage })
    }
    const timer = setTimeout(
      () => finish({ ok: false, reason: "timeout" }),
      opts.timeoutMs
    )
    const poll = setInterval(() => {
      if (popup.closed) finish({ ok: false, reason: "closed" })
    }, 500)
    window.addEventListener("message", onMessage)
  })
}
