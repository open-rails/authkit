// @vitest-environment jsdom
// DPoP is the app's choice, default bearer: tokens are bound only when the
// app asks (dpop: true) or the issuer refuses an unbound request with
// invalid_dpop_proof (RFC 9449 §5), and a bound token is always sent with a
// proof (RFC 9449 §7), a bearer one as Bearer (RFC 6750 §2.1).
import { afterEach, describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { createIssuerClient } from "./issuer.ts"
import { createResourceTokens } from "./resource.ts"
import { authError, authResult, json } from "./testing.ts"

afterEach(() => {
  vi.unstubAllGlobals()
})

const ISSUER = "https://issuer.example"
const token = (claims: Record<string, unknown>) =>
  `h.${btoa(JSON.stringify(claims)).replace(/=+$/, "")}.s`

type Seen = { url: string; dpop: boolean; auth: string }

// An issuer that requires DPoP or not, and an API beside it.
function issuer(requires: boolean) {
  let nonce = ""
  const seen: Seen[] = []
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const headers = new Headers(init?.headers)
    seen.push({
      url: new URL(url).pathname,
      dpop: headers.has("DPoP"),
      auth: (headers.get("Authorization") ?? "").split(" ")[0],
    })
    if (url.endsWith("/.well-known/openid-configuration"))
      return json(200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth2/authorize`,
        token_endpoint: `${ISSUER}/oauth2/token`,
        authorization_response_iss_parameter_supported: true,
      })
    if (url.endsWith("/oauth2/token")) {
      const bound = headers.has("DPoP")
      if (requires && !bound)
        return json(400, {
          error: "invalid_dpop_proof",
          error_description: "a DPoP proof is required",
        })
      return json(200, {
        access_token: token({ sub: "u1", exp: 9_999_999_999 }),
        token_type: bound ? "DPoP" : "Bearer",
        expires_in: 300,
        id_token: token({
          iss: ISSUER,
          aud: "console",
          nonce,
          exp: 9_999_999_999,
          sub: "u1",
        }),
      })
    }
    return json(200, {})
  })
  const setNonce = (n: string) => (nonce = n)
  return { fetch, seen, setNonce }
}

async function signIn(requires: boolean, dpop?: boolean) {
  const { fetch, seen, setNonce } = issuer(requires)
  const client = createIssuerClient({
    issuer: ISSUER,
    clientId: "console",
    redirectUri: "https://app.example/callback",
    dpop,
    persist: false,
    fetch,
  })
  const assign = vi.fn()
  vi.stubGlobal("location", {
    ...window.location,
    assign,
    href: "https://app.example/",
  })
  await client.signIn()
  const sent = new URL(assign.mock.calls.at(-1)![0] as string)
  setNonce(sent.searchParams.get("nonce")!)
  await client.completeSignIn(
    `https://app.example/callback?code=c&state=${sent.searchParams.get("state")}&iss=${encodeURIComponent(ISSUER)}`
  )
  expect(client.getSnapshot()).toMatchObject({ status: "authenticated" })
  seen.length = 0
  await client.authFetch(`${ISSUER}/api/thing`)
  return { authorize: sent, seen }
}

describe("issuer client DPoP", () => {
  it("is bearer by default", async () => {
    const { authorize, seen } = await signIn(false)
    expect(authorize.searchParams.has("dpop_jkt")).toBe(false)
    expect(seen).toEqual([{ url: "/api/thing", dpop: false, auth: "Bearer" }])
  })

  it("binds when the app asks", async () => {
    const { authorize, seen } = await signIn(false, true)
    expect(authorize.searchParams.get("dpop_jkt")).toBeTruthy()
    expect(seen).toEqual([{ url: "/api/thing", dpop: true, auth: "DPoP" }])
  })

  it("binds when the issuer requires it", async () => {
    const { seen } = await signIn(true)
    expect(seen).toEqual([{ url: "/api/thing", dpop: true, auth: "DPoP" }])
  })
})

describe("resource tokens DPoP", () => {
  const exchange = async (requires: boolean, dpop?: boolean) => {
    const { fetch, seen } = issuer(requires)
    const tokens = createResourceTokens(
      { clientId: "host", tokenEndpoint: `${ISSUER}/oauth2/token`, dpop },
      { fetch, session: async () => ({ token: "session", userId: "u1" }) }
    )
    await tokens.resourceFetch(`${ISSUER}/api/thing`, {
      resource: "https://api.example",
    })
    return seen.map(({ url, dpop, auth }) => ({ url, dpop, auth }))
  }

  it("is bearer by default", async () => {
    expect(await exchange(false)).toEqual([
      { url: "/oauth2/token", dpop: false, auth: "" },
      { url: "/api/thing", dpop: false, auth: "Bearer" },
    ])
  })

  it("binds when the app asks", async () => {
    expect(await exchange(false, true)).toEqual([
      { url: "/oauth2/token", dpop: true, auth: "" },
      { url: "/api/thing", dpop: true, auth: "DPoP" },
    ])
  })

  it("binds when the issuer requires it", async () => {
    expect(await exchange(true)).toEqual([
      { url: "/oauth2/token", dpop: false, auth: "" },
      { url: "/oauth2/token", dpop: true, auth: "" },
      { url: "/api/thing", dpop: true, auth: "DPoP" },
    ])
  })
})

describe("sign-in sessions DPoP", () => {
  const bearerToken = (sub: string, cnf?: string) =>
    token({ sub, exp: 9_999_999_999, ...(cnf ? { cnf: { jkt: cnf } } : {}) })
  const signedIn = (access: string) =>
    authResult("complete", {
      token_set: {
        access_token: access,
        token_type: "Bearer",
        expires_in: 900,
        refresh_token: null,
      },
    })

  // An AuthKit that requires DPoP or not; it binds a session whose sign-in
  // proves a key.
  function authkit(requires: boolean) {
    const seen: Seen[] = []
    const fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), "https://app.example")
        const headers = new Headers(init?.headers)
        seen.push({
          url: url.pathname,
          dpop: headers.has("DPoP"),
          auth: (headers.get("Authorization") ?? "").split(" ")[0],
        })
        if (
          url.pathname === "/api/v1/password/login" ||
          url.pathname === "/api/v1/token"
        ) {
          if (requires && !headers.has("DPoP"))
            return authError(401, "sender_proof_required")
          return json(
            200,
            signedIn(bearerToken("u1", headers.has("DPoP") ? "jkt" : undefined))
          )
        }
        return json(200, {})
      }
    )
    return { fetch, seen }
  }

  const run = async (requires: boolean, dpop?: boolean) => {
    const { fetch, seen } = authkit(requires)
    vi.stubGlobal("location", {
      ...window.location,
      href: "https://app.example/",
    })
    const client = createAuthClient({ fetch, dpop, sessionHint: false })
    await client.signInWithPassword({ identifier: "a@b.c", password: "pw" })
    await client.authFetch("https://app.example/api/thing")
    await client.refresh()
    return seen.filter((s) => s.url !== "/api/v1/capabilities")
  }

  it("is bearer by default", async () => {
    expect(await run(false)).toEqual([
      { url: "/api/v1/password/login", dpop: false, auth: "" },
      { url: "/api/thing", dpop: false, auth: "Bearer" },
      { url: "/api/v1/token", dpop: false, auth: "" },
    ])
  })

  it("binds when the app asks", async () => {
    expect(await run(false, true)).toEqual([
      { url: "/api/v1/password/login", dpop: true, auth: "" },
      { url: "/api/thing", dpop: true, auth: "DPoP" },
      { url: "/api/v1/token", dpop: true, auth: "" },
    ])
  })

  it("binds when the AuthKit requires it", async () => {
    expect(await run(true)).toEqual([
      { url: "/api/v1/password/login", dpop: false, auth: "" },
      { url: "/api/v1/password/login", dpop: true, auth: "" },
      { url: "/api/thing", dpop: true, auth: "DPoP" },
      { url: "/api/v1/token", dpop: true, auth: "" },
    ])
  })
})
