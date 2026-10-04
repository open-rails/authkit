// Test helpers (not exported from the package).
import { onTestFinished, vi } from "vitest"

import type { AuthResult } from "./types.ts"

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

export const tokenSet = (sub: string, exp?: number) => ({
  access_token: jwt(sub, exp),
  token_type: "Bearer",
  expires_in: 900,
  refresh_token: null as string | null,
})

const NO_STEP = {
  token_set: null,
  user: null,
  created: false,
  return_to: null,
  fresh_auth: null,
  device_key: null,
  second_factor: null,
  enrollment: null,
  verification: null,
  recovery: null,
  device_verification: null,
}

// An AuthResult with every field present, as AuthKit sends it.
export const authResult = (
  status: AuthResult["status"],
  fields: Partial<AuthResult> = {}
): AuthResult => ({ ...NO_STEP, status, ...fields })

export const complete = (
  sub: string,
  exp?: number,
  fields: Partial<AuthResult> = {}
) => authResult("complete", { token_set: tokenSet(sub, exp), ...fields })

// A 200 AuthResult that signs sub in.
export const tokens = (sub: string, exp?: number) =>
  json(200, complete(sub, exp))

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

// A platform authenticator for the current test: PublicKeyCredential exists
// and navigator.credentials.get answers with one fixed passkey, whose body
// AuthKit receives as passkeyAssertion.
export function stubPasskey() {
  const bytes = (...b: number[]) => new Uint8Array(b).buffer
  class FakePasskey {
    id = "cred"
    rawId = bytes(1, 2)
    type = "public-key"
    authenticatorAttachment = "platform"
    response = {
      clientDataJSON: bytes(3),
      authenticatorData: bytes(4),
      signature: bytes(5),
      userHandle: bytes(6),
    }
    getClientExtensionResults() {
      return {}
    }
  }
  const get = vi.fn(
    async (options: CredentialRequestOptions): Promise<unknown> =>
      options.publicKey ? new FakePasskey() : null
  )
  vi.stubGlobal("PublicKeyCredential", FakePasskey)
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: { get },
  })
  onTestFinished(() => {
    vi.unstubAllGlobals()
    delete (navigator as { credentials?: unknown }).credentials
  })
  return get
}

export const passkeyAssertion = {
  id: "cred",
  rawId: "AQI",
  type: "public-key",
  authenticatorAttachment: "platform",
  clientExtensionResults: {},
  response: {
    clientDataJSON: "Aw",
    authenticatorData: "BA",
    signature: "BQ",
    userHandle: "Bg",
  },
}

// Passkey request options as AuthKit's begin routes answer them.
export const passkeyOptions = () =>
  json(200, {
    publicKey: {
      challenge: "AQID",
      rpId: "x.test",
      allowCredentials: [{ type: "public-key", id: "AQI" }],
      userVerification: "required",
    },
  })
