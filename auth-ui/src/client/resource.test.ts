// @vitest-environment jsdom
// Resource tokens bound to a group (RFC 8693 exchange naming group_id): the
// group goes in the exchange form, tokens for two groups never share a cache
// entry, and DPoP binding holds, a bound session proving its own key.
import { describe, expect, it, vi } from "vitest"

import type { DPoPKey } from "./dpop.ts"
import { createResourceTokens } from "./resource.ts"
import { json } from "./testing.ts"

const ISSUER = "https://issuer.example"

type Call = { url: string; form: URLSearchParams | null; dpop: string | null }

// An issuer minting a new token per exchange (bound when proved), and an API.
function issuer() {
  const calls: Call[] = []
  let n = 0
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input))
    const headers = new Headers(init?.headers)
    const form =
      typeof init?.body === "string" ? new URLSearchParams(init.body) : null
    calls.push({ url: url.pathname, form, dpop: headers.get("DPoP") })
    if (url.pathname === "/oauth2/token")
      return json(200, {
        access_token: `at-${++n}-${form?.get("group_id") ?? "none"}`,
        token_type: headers.has("DPoP") ? "DPoP" : "Bearer",
        expires_in: 900,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      })
    return json(200, {})
  })
  return { fetch, calls }
}

// A stand-in DPoP key whose proofs name it.
const fakeKey = (name: string): DPoPKey => ({
  thumbprint: `${name}-jkt`,
  proof: async () => `proof-of-${name}`,
})

const tokensFor = (
  fetch: typeof globalThis.fetch,
  opts: { dpop?: boolean; sessionKey?: DPoPKey } = {}
) =>
  createResourceTokens(
    {
      clientId: "console",
      tokenEndpoint: `${ISSUER}/oauth2/token`,
      dpop: opts.dpop,
    },
    {
      fetch,
      session: async () => ({
        token: "session",
        userId: "u1",
        ...(opts.sessionKey ? { key: async () => opts.sessionKey! } : {}),
      }),
    }
  )

const resource = "https://api.example"

describe("resource tokens bound to a group", () => {
  it("sends the group as group_id, and none without one", async () => {
    const { fetch, calls } = issuer()
    const tokens = tokensFor(fetch)
    const bound = await tokens.getResourceToken({
      resource,
      scope: "read",
      group: "m-1",
    })
    await tokens.getResourceToken({ resource, scope: "read" })
    const exchanges = calls.filter((c) => c.url === "/oauth2/token")
    expect(exchanges.map((c) => c.form?.get("group_id") ?? null)).toEqual([
      "m-1",
      null,
    ])
    expect(exchanges[0].form?.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:token-exchange"
    )
    expect(bound).toMatchObject({ group: "m-1", resource, scope: ["read"] })
    expect(bound).not.toHaveProperty("proofKey")
    expect(bound).not.toHaveProperty("userId")
  })

  it("keeps each group's token apart: a switch never reuses another group's", async () => {
    const { fetch, calls } = issuer()
    const tokens = tokensFor(fetch)
    const a = await tokens.getResourceToken({ resource, group: "m-1" })
    const b = await tokens.getResourceToken({ resource, group: "m-2" })
    const none = await tokens.getResourceToken({ resource })
    const aAgain = await tokens.getResourceToken({ resource, group: "m-1" })
    expect(new Set([a.accessToken, b.accessToken, none.accessToken]).size).toBe(
      3
    )
    expect(b.accessToken).toContain("m-2")
    expect(aAgain.accessToken).toBe(a.accessToken)
    expect(calls.filter((c) => c.url === "/oauth2/token")).toHaveLength(3)

    const res = await tokens.resourceFetch(`${ISSUER}/api/thing`, {
      resource,
      group: "m-2",
    })
    expect(res.status).toBe(200)
    const call = calls.at(-1)!
    expect(call.url).toBe("/api/thing")
    expect(calls.filter((c) => c.url === "/oauth2/token")).toHaveLength(3)
  })

  it("binds with this frontend's key when the app asks", async () => {
    const { fetch, calls } = issuer()
    const tokens = tokensFor(fetch, { dpop: true })
    const t = await tokens.getResourceToken({ resource, group: "m-1" })
    expect(t.tokenType).toBe("DPoP")
    await tokens.resourceFetch(`${ISSUER}/api/thing`, {
      resource,
      group: "m-1",
    })
    expect(calls.map((c) => [c.url, !!c.dpop])).toEqual([
      ["/oauth2/token", true],
      ["/api/thing", true],
    ])
  })

  it("proves a bound session's own key, the only one its token is exchanged with", async () => {
    const { fetch, calls } = issuer()
    const tokens = tokensFor(fetch, { sessionKey: fakeKey("session") })
    const t = await tokens.getResourceToken({ resource, group: "m-1" })
    expect(t.tokenType).toBe("DPoP")
    await tokens.resourceFetch(`${ISSUER}/api/thing`, {
      resource,
      group: "m-1",
    })
    expect(calls.map((c) => [c.url, c.dpop])).toEqual([
      ["/oauth2/token", "proof-of-session"],
      ["/api/thing", "proof-of-session"],
    ])
  })
})
