import { test, open, seed, login } from "./browser"
import { expect } from "@playwright/test"

// This is the real authorization server. The only interception below changes
// the authorization request nonce to prove a genuine signed mismatch is refused.
test("AK-UI-16: AK-J29-C07: issuer proof binds a server nonce and retains only the current ID token", async ({
  page,
  request,
  context,
}) => {
  const alice = await seed(request)
  const bob = await seed(request)
  await open(page)
  expect(
    await page.evaluate(
      () =>
        typeof (window.ak.issuer as unknown as { getIDToken?: unknown })
          .getIDToken
    )
  ).toBe("function")
  const idToken = () =>
    page.evaluate(() =>
      (
        window.ak.issuer as unknown as { getIDToken(): string | null }
      ).getIDToken()
    )
  expect(await idToken()).toBeNull()
  for (const nonce of ["", " ", "\u0000"]) {
    const error = await page.evaluate(async (nonce) => {
      try {
        await window.ak.issuer.signIn({ nonce })
        return null
      } catch (error) {
        return (error as { error?: string }).error
      }
    }, nonce)
    expect(error).toBe("invalid_request")
  }
  async function signIn(
    who: typeof alice,
    nonce?: string,
    waitForExchange = false,
    observedNonce = nonce
  ) {
    const authorization = context.waitForEvent(
      "request",
      (r) => new URL(r.url()).pathname === "/oauth2/authorize"
    )
    const popupReady = page.waitForEvent("popup")
    await page.evaluate((nonce) => {
      window.ak.issuerResult = undefined
      const options = {
        popup: true,
        prompt: "login" as const,
        maxAge: 0,
        ...(nonce === undefined ? {} : { nonce }),
      }
      void window.ak.issuer.signIn(options).then(
        () => {
          window.ak.issuerResult = { ok: true }
        },
        (error) => {
          window.ak.issuerResult = {
            ok: false,
            error: (error as { error?: string }).error,
          }
        }
      )
    }, nonce)
    const popup = await popupReady
    const requested = new URL((await authorization).url())
    expect(requested.searchParams.get("code_challenge_method")).toBe("S256")
    expect(requested.searchParams.get("code_challenge")).toBeTruthy()
    expect(requested.searchParams.get("state")).toBeTruthy()
    expect(requested.searchParams.get("nonce")).toBeTruthy()
    expect(requested.searchParams.get("state")).not.toBe(
      requested.searchParams.get("nonce")
    )
    if (nonce !== undefined)
      expect(requested.searchParams.get("nonce")).toBe(observedNonce)
    await popup.waitForURL(
      (url) =>
        url.pathname === "/authorize" && url.searchParams.has("authorization")
    )
    await expect(popup.getByTestId("session-status")).not.toHaveText("loading")
    expect((await login(popup, who)).status).toBe("complete")
    let release: (() => void) | undefined
    let arrived: (() => void) | undefined
    const pending = new Promise<void>((resolve) => {
      arrived = resolve
    })
    if (waitForExchange)
      await page.route(
        "**/oauth2/token",
        async (route) => {
          arrived?.()
          await new Promise<void>((resolve) => {
            release = resolve
          })
          await route.continue()
        },
        { times: 1 }
      )
    await popup.evaluate(async () => {
      const id = new URLSearchParams(location.search).get("authorization")!
      await window.ak.client.getOAuthAuthorization(id)
      const answer = await window.ak.client.approveOAuthAuthorization(id, {
        consent: true,
      })
      location.assign(answer.redirect_to)
    })
    if (waitForExchange) {
      await pending
      expect(await idToken()).toBeNull()
      release?.()
    }
    await expect
      .poll(() => page.evaluate(() => window.ak.issuerResult))
      .toBeTruthy()
    return page.evaluate(() => window.ak.issuerResult!)
  }
  expect(await signIn(alice, "server-issued-proof-nonce")).toEqual({ ok: true })
  const decode = (raw: string) =>
    JSON.parse(Buffer.from(raw.split(".")[1], "base64url").toString()) as {
      sub: string
      nonce: string
    }
  expect(decode((await idToken())!)).toMatchObject({
    sub: alice.id,
    nonce: "server-issued-proof-nonce",
  })
  expect(await signIn(bob, undefined, true)).toEqual({ ok: true })
  expect(decode((await idToken())!).sub).toBe(bob.id)
  await page.evaluate(() => window.ak.issuer.signOut({ redirect: false }))
  expect(await idToken()).toBeNull()
  expect(await signIn(alice, "current-proof-before-refusal")).toEqual({
    ok: true,
  })
  await context.route(
    "**/oauth2/authorize?**",
    (route) => {
      const url = new URL(route.request().url())
      url.searchParams.set("nonce", "different-real-issued-nonce")
      return route.continue({ url: url.toString() })
    },
    { times: 1 }
  )
  expect(
    await signIn(
      bob,
      "expected-proof-nonce",
      false,
      "different-real-issued-nonce"
    )
  ).toEqual({
    ok: false,
    error: "invalid_grant",
  })
  expect(await idToken()).toBeNull()
})
