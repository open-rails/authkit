import path from "node:path"

import { expect, test, type Page } from "@playwright/test"

import type { AuthClient } from "../src/client/index.ts"
import { outbox, totp } from "./support/api"

type Mod = typeof import("../src/client/index.ts")
type Win = { auth: AuthClient; mod: Mod }

const dist = path.resolve(import.meta.dirname, "../dist")

// Serves the built package (and its shared chunks) and installs a fresh client
// as window.auth.
async function loadClient(page: Page) {
  await page.route("**/__auth-ui/*.js", (route, req) =>
    route.fulfill({
      path: path.join(dist, path.basename(new URL(req.url()).pathname)),
      contentType: "text/javascript",
    })
  )
  await page.goto("/")
  await page.evaluate(async () => {
    const w = window as unknown as Win
    w.mod = await import(/* @vite-ignore */ "/__auth-ui/client.js")
    w.auth = w.mod.createAuthClient()
  })
}

const snapshot = (page: Page) =>
  page.evaluate(() => (window as unknown as Win).auth.getSnapshot())

test("built client: register, TOTP login, refresh, restore, logout", async ({
  page,
  request,
  context,
}) => {
  await loadClient(page)
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `client-${id}@example.test`
  const password = "Correct-horse-battery-9"

  const reg = await page.evaluate(
    (input) => (window as unknown as Win).auth.register(input),
    { identifier: email, username: `c${id}`, password }
  )
  expect(reg).toMatchObject({ next_action: "verify_email", signedIn: false })

  const code = (await outbox(request, email)).find(
    (m) => m.kind === "verification"
  )?.code
  expect(
    await page.evaluate(
      (input) => (window as unknown as Win).auth.confirmVerification(input),
      { identifier: email, code: code! }
    )
  ).toEqual({ kind: "session" })
  expect(await snapshot(page)).toMatchObject({ status: "authenticated" })

  // TOTP codes must come from increasing steps; start early in a step.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()
  const started = await page.evaluate(() =>
    (window as unknown as Win).auth.enableTwoFactor({ method: "totp" })
  )
  expect(started.kind).toBe("totp_started")
  const secret = (started as { secret: string }).secret
  const enabled = await page.evaluate(
    (code) =>
      (window as unknown as Win).auth.enableTwoFactor({ method: "totp", code }),
    totp(secret, now)
  )
  expect(enabled).toMatchObject({ kind: "enabled", method: "totp" })

  await page.evaluate(() => (window as unknown as Win).auth.signOut())
  expect(await snapshot(page)).toEqual({
    status: "anonymous",
    reason: "signed_out",
    continuation: null,
  })
  expect(
    (await context.cookies()).find((c) => c.name === "authkit_rt")
  ).toBeUndefined()

  const challenge = await page.evaluate(
    (input) => (window as unknown as Win).auth.signInWithPassword(input),
    { identifier: email, password }
  )
  expect(challenge).toMatchObject({ kind: "2fa_required", method: "totp" })
  expect(
    await page.evaluate(
      ([c, code]) =>
        (window as unknown as Win).auth.verifyTwoFactor({
          userId: (c as { userId: string }).userId,
          challenge: (c as { challenge: string }).challenge,
          code: code as string,
        }),
      [challenge, totp(secret, now + 30_000)] as const
    )
  ).toEqual({ kind: "session" })
  const signedIn = await snapshot(page)
  expect(signedIn.status).toBe("authenticated")

  const cookie = (await context.cookies()).find((c) => c.name === "authkit_rt")
  expect(
    await page.evaluate(() => (window as unknown as Win).auth.refresh())
  ).toBe(true)
  expect(
    (await context.cookies()).find((c) => c.name === "authkit_rt")?.value
  ).not.toBe(cookie?.value)

  const me = await page.evaluate(async () => {
    const { auth } = window as unknown as Win
    const res = await auth.authFetch("/api/v1/me")
    return { status: res.status, profile: await auth.getMe() }
  })
  expect(me).toMatchObject({ status: 200, profile: { email } })

  const fresh = await page.evaluate(
    (pw) => (window as unknown as Win).auth.stepUpWithPassword(pw),
    password
  )
  expect(fresh.step_up_required_for_sensitive_actions).toBe(false)

  // A second client stands in for a reload: the cookie alone restores it.
  const restored = await page.evaluate(async () => {
    const w = window as unknown as Win
    const other = w.mod.createAuthClient()
    const stop = other.start()
    while (other.getSnapshot().status === "loading") {
      await new Promise((r) => setTimeout(r, 20))
    }
    stop()
    return other.getSnapshot()
  })
  expect(restored).toMatchObject({
    status: "authenticated",
    userId: (signedIn as { userId: string }).userId,
  })

  await page.evaluate(() => (window as unknown as Win).auth.signOut())
  const afterLogout = await page.evaluate(async () => {
    const other = (window as unknown as Win).mod.createAuthClient()
    const stop = other.start()
    while (other.getSnapshot().status === "loading") {
      await new Promise((r) => setTimeout(r, 20))
    }
    stop()
    return other.getSnapshot()
  })
  expect(afterLogout).toEqual({
    status: "anonymous",
    reason: "initial",
    continuation: null,
  })
})
