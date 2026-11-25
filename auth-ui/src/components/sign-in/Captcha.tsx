import { useEffect, useRef } from "react"

import { useAuthClient, useCapabilities } from "#authui/react/context"

// The providers' explicit-render APIs, as far as Captcha uses them.
type Widgets = {
  render: (el: HTMLElement, options: Record<string, unknown>) => string
  execute: (id: string, options?: { async: true }) => unknown
  reset: (id: string) => void
  remove: (id: string) => void
}

const scripts: Record<string, { url: string; global: string }> = {
  turnstile: {
    url: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
    global: "turnstile",
  },
  hcaptcha: {
    url: "https://js.hcaptcha.com/1/api.js?render=explicit&recaptchacompat=off",
    global: "hcaptcha",
  },
}

// How long a challenge that needs the person may wait for them.
const TOKEN_TIMEOUT_MS = 120_000

const loading = new Map<string, Promise<Widgets>>()

function loadWidgets(provider: string): Promise<Widgets> {
  const script = scripts[provider]
  if (!script)
    return Promise.reject(new Error(`unknown captcha provider ${provider}`))
  const ready = () =>
    (window as unknown as Record<string, Widgets | undefined>)[script.global]
  let promise = loading.get(provider)
  if (!promise) {
    promise = new Promise<Widgets>((resolve, reject) => {
      const loaded = ready()
      if (loaded) return resolve(loaded)
      const el = document.createElement("script")
      el.src = script.url
      el.async = true
      el.onload = () => {
        const widgets = ready()
        if (widgets) resolve(widgets)
        else reject(new Error(`${provider} did not load`))
      }
      el.onerror = () => {
        loading.delete(provider)
        reject(new Error(`${provider} did not load`))
      }
      document.head.appendChild(el)
    })
    loading.set(provider, promise)
  }
  return promise
}

// The bot challenge GET /capabilities names (AuthKit's Deps.Captcha), for
// forms that send a code: while it is mounted, the client's
// startPasswordless and register carry a fresh token. It stays invisible
// unless the provider needs the person to act. The host's CSP must allow the
// provider's script and frame.
export function Captcha() {
  const client = useAuthClient()
  const { capabilities } = useCapabilities()
  const provider = capabilities?.captcha?.provider
  const siteKey = capabilities?.captcha?.site_key
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = box.current
    if (!provider || !siteKey || !el) return
    let gone = false
    let widgets: Widgets | undefined
    let id: string | undefined
    let used = false
    let waiting: {
      resolve: (token: string) => void
      reject: (err: Error) => void
    } | null = null
    const settle = (token: string | null, err?: Error) => {
      const w = waiting
      waiting = null
      if (!w) return
      if (token) w.resolve(token)
      else w.reject(err ?? new Error("captcha failed"))
    }
    const mounted = loadWidgets(provider).then((loaded) => {
      if (gone) return
      widgets = loaded
      id = loaded.render(el, {
        sitekey: siteKey,
        ...(provider === "turnstile"
          ? { execution: "execute", appearance: "interaction-only" }
          : { size: "invisible" }),
        callback: (token: string) => settle(token),
        "error-callback": () => settle(null),
        "expired-callback": () => settle(null),
        "close-callback": () => settle(null),
      })
    })
    const source = async (): Promise<string> => {
      await mounted
      if (!widgets || id === undefined) throw new Error("captcha unavailable")
      settle(null, new Error("superseded"))
      const token = new Promise<string>((resolve, reject) => {
        waiting = { resolve, reject }
      })
      // A token passes once: each start solves the challenge again.
      if (used) widgets.reset(id)
      used = true
      // hCaptcha's execute answers a promise; Turnstile's answers through
      // the callback and takes no options.
      const run =
        provider === "hcaptcha"
          ? widgets.execute(id, { async: true })
          : widgets.execute(id)
      if (run instanceof Promise)
        run.then(
          (out: { response?: string }) => settle(out?.response ?? null),
          () => settle(null)
        )
      const timer = setTimeout(
        () => settle(null, new Error("captcha timed out")),
        TOKEN_TIMEOUT_MS
      )
      return token.finally(() => clearTimeout(timer))
    }
    const remove = client.addCaptcha(source)
    return () => {
      gone = true
      remove()
      settle(null, new Error("unmounted"))
      if (widgets && id !== undefined) widgets.remove(id)
    }
  }, [client, provider, siteKey])

  if (!provider || !siteKey) return null
  return <div ref={box} className="flex justify-center empty:hidden" />
}
