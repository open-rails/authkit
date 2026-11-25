// Creates a passkey in a top-level window where a cross-origin iframe
// cannot (Safari refuses navigator.credentials.create there). The window is
// AuthKit's GET /passkeys/window on this page's own origin; the iframe keeps
// the session, begins and finishes the ceremony, and the window only runs
// create() on a click. Messages: READY, OPTIONS, RESULT (AUTHKIT_PASSKEY_*).

import { AuthKitError } from "./errors.ts"
export { inCrossOriginFrame } from "./frame.ts"
import { POPUP_CLOSE_GRACE_MS, randomNonce } from "./popup.ts"

// The credential the window created, its binary fields as ArrayBuffers.
export type WindowCredential = {
  id: string
  rawId: ArrayBuffer
  type: string
  authenticatorAttachment?: string
  clientExtensionResults: AuthenticationExtensionsClientOutputs
  response: {
    clientDataJSON: ArrayBuffer
    attestationObject: ArrayBuffer
    transports: string[]
  }
}

export type PasskeyWindowLabels = { title: string; create: string }

const WINDOW_TIMEOUT_MS = 5 * 60_000

// A failure of the window, as auth-ui's popup errors: popup_blocked,
// popup_closed or popup_timeout.
const windowError = (reason: string) => {
  const code = `popup_${reason}`
  return new AuthKitError(0, { type: "local", code, message: code })
}

// Opens the window now (call from a click), then hands it begin's options
// and resolves with the credential it created. A DOMException the browser
// raised there rejects with its name.
export function createInWindow(
  windowUrl: string,
  begin: () => Promise<PublicKeyCredentialCreationOptions>,
  labels: PasskeyWindowLabels
): Promise<WindowCredential> {
  const nonce = randomNonce()
  const origin = new URL(windowUrl, window.location.href).origin
  const w = 420
  const h = 360
  const left = (window.screenX ?? 0) + ((window.outerWidth || w) - w) / 2
  const top = (window.screenY ?? 0) + ((window.outerHeight || h) - h) / 2
  const popup = window.open(
    `${windowUrl}#nonce=${nonce}`,
    "authkit_passkey",
    `popup=yes,width=${w},height=${h},left=${left},top=${top}`
  )
  if (!popup) return Promise.reject(windowError("blocked"))
  const options = begin()
  options.catch(() => undefined)
  return new Promise<WindowCredential>((resolve, reject) => {
    let closing: ReturnType<typeof setTimeout> | undefined
    const finish = (settle: () => void) => {
      clearTimeout(timer)
      clearInterval(poll)
      clearTimeout(closing)
      window.removeEventListener("message", onMessage)
      try {
        popup.close()
      } catch {
        // already gone
      }
      settle()
    }
    const onMessage = (ev: MessageEvent) => {
      const data = ev.data as Record<string, unknown> | null
      if (ev.source !== popup || ev.origin !== origin || data?.nonce !== nonce)
        return
      if (data.type === "AUTHKIT_PASSKEY_READY") {
        options.then(
          (publicKey) =>
            popup.postMessage(
              {
                type: "AUTHKIT_PASSKEY_OPTIONS",
                nonce,
                options: publicKey,
                labels,
              },
              origin
            ),
          (err: unknown) => finish(() => reject(err))
        )
      } else if (data.type === "AUTHKIT_PASSKEY_RESULT") {
        const name = data.error
        if (typeof name === "string")
          finish(() =>
            reject(new DOMException("passkey creation failed", name))
          )
        else
          finish(() => resolve(data.credential as unknown as WindowCredential))
      }
    }
    const timer = setTimeout(
      () => finish(() => reject(windowError("timeout"))),
      WINDOW_TIMEOUT_MS
    )
    // The window posts its result and then closes itself.
    const poll = setInterval(() => {
      if (!popup.closed) return
      clearInterval(poll)
      closing = setTimeout(
        () => finish(() => reject(windowError("closed"))),
        POPUP_CLOSE_GRACE_MS
      )
    }, 500)
    window.addEventListener("message", onMessage)
  })
}
