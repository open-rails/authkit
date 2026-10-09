// @vitest-environment jsdom
// The callback's refusals of answers a real issuer would not send: another
// issuer's, an unknown state, an ID token for another sign-in.
import { afterEach, describe, expect, it, vi } from "vitest"

import { createIssuerClient } from "./issuer.ts"
import { OAuthError } from "./oauthError.ts"
import { json } from "./testing.ts"

afterEach(() => {
  vi.unstubAllGlobals()
})

const ISSUER = "https://issuer.example"
const token = (claims: Record<string, unknown>) =>
  `h.${btoa(JSON.stringify(claims)).replace(/=+$/, "")}.s`

function issuerWith(idClaims: (nonce: string) => Record<string, unknown>) {
  let nonce = ""
  const fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    if (url.endsWith("/.well-known/openid-configuration"))
      return json(200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/oauth2/authorize`,
        token_endpoint: `${ISSUER}/oauth2/token`,
        authorization_response_iss_parameter_supported: true,
      })
    return json(200, {
      access_token: token({ sub: "u1", exp: 9_999_999_999 }),
      token_type: "Bearer",
      expires_in: 300,
      id_token: token(idClaims(nonce)),
    })
  })
  const client = createIssuerClient({
    issuer: ISSUER,
    clientId: "console",
    redirectUri: "https://app.example/callback",
    dpop: false,
    persist: false,
    fetch,
  })
  const assign = vi.fn()
  vi.stubGlobal("location", {
    ...window.location,
    assign,
    href: "https://app.example/",
  })
  const begin = async () => {
    await client.signIn()
    const sent = new URL(assign.mock.calls.at(-1)![0] as string)
    nonce = sent.searchParams.get("nonce")!
    return sent.searchParams.get("state")!
  }
  return { client, fetch, begin }
}

const refusal = (p: Promise<unknown>) =>
  p.then(
    () => "accepted",
    (e: unknown) => (e instanceof OAuthError ? e.error : String(e))
  )

describe("issuer callback", () => {
  const good = (nonce: string) => ({
    iss: ISSUER,
    aud: "console",
    nonce,
    exp: 9_999_999_999,
    sub: "u1",
  })

  it("finishes a sign-in it started, once", async () => {
    const { client, begin } = issuerWith(good)
    const state = await begin()
    const callback = `https://app.example/callback?code=c&state=${state}&iss=${encodeURIComponent(ISSUER)}`
    expect(await client.completeSignIn(callback)).toEqual({
      kind: "signed_in",
      returnTo: undefined,
    })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
    expect(await refusal(client.completeSignIn(callback))).toBe(
      "invalid_request"
    )
  })

  it("ignores a page that is no callback", async () => {
    const { client } = issuerWith(good)
    expect(
      await client.completeSignIn("https://app.example/callback")
    ).toBeNull()
  })

  it("refuses an answer from another issuer, an unknown state and an issuer error", async () => {
    const { client, fetch, begin } = issuerWith(good)
    const state = await begin()
    const calls = fetch.mock.calls.length
    expect(
      await refusal(
        client.completeSignIn(
          `https://app.example/callback?code=c&state=${state}&iss=https://evil.example`
        )
      )
    ).toBe("invalid_request")
    expect(fetch.mock.calls.length).toBe(calls)
    expect(
      await refusal(
        client.completeSignIn(
          "https://app.example/callback?code=c&state=r.forged"
        )
      )
    ).toBe("invalid_request")
    const denied = await begin()
    expect(
      await refusal(
        client.completeSignIn(
          `https://app.example/callback?error=access_denied&state=${denied}&iss=${encodeURIComponent(ISSUER)}`
        )
      )
    ).toBe("access_denied")
    expect(client.getSnapshot()).toMatchObject({ status: "anonymous" })
  })

  it.each([
    ["another nonce", (n: string) => ({ ...good(n), nonce: "other" })],
    ["another audience", (n: string) => ({ ...good(n), aud: "someone-else" })],
    [
      "another issuer",
      (n: string) => ({ ...good(n), iss: "https://evil.example" }),
    ],
    ["expired", (n: string) => ({ ...good(n), exp: 1 })],
  ])("refuses an ID token with %s", async (_, claims) => {
    const { client, begin } = issuerWith(claims)
    const state = await begin()
    expect(
      await refusal(
        client.completeSignIn(
          `https://app.example/callback?code=c&state=${state}&iss=${encodeURIComponent(ISSUER)}`
        )
      )
    ).toBe("invalid_grant")
    expect(client.getSnapshot()).toMatchObject({ status: "anonymous" })
  })
})
