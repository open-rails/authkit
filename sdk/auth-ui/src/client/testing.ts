// Test helpers (not exported from the package).
import { vi } from "vitest"

export const jwt = (sub: string, exp = 9_999_999_999) =>
  `h.${btoa(JSON.stringify({ sub, exp })).replace(/=+$/, "")}.s`

export const json = (
  status: number,
  body?: unknown,
  headers: Record<string, string> = {}
) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  })

export const tokens = (sub: string, exp?: number) =>
  json(200, {
    access_token: jwt(sub, exp),
    token_type: "Bearer",
    expires_in: 900,
  })

export const authError = (
  status: number,
  code: string,
  metadata?: Record<string, unknown>,
  headers?: Record<string, string>
) =>
  json(status, { error: { type: "", code, message: code, metadata } }, headers)

export function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

type Route = (
  init: RequestInit & { url: string }
) => Response | Promise<Response>

// Routes by "METHOD /path" (query ignored); unmatched calls fail loudly.
export function stubFetch(routes: Record<string, Route | Response[]>) {
  return vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input)
    const key = `${init.method ?? "GET"} ${url.replace(/^https?:\/\/[^/]+/, "").split("?")[0]}`
    const route = routes[key]
    if (!route) throw new Error(`unexpected fetch ${key}`)
    if (Array.isArray(route)) {
      const next = route.shift()
      if (!next) throw new Error(`no more responses for ${key}`)
      return next
    }
    return route({ ...init, url })
  })
}
