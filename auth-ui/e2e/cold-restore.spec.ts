import path from "node:path"

import { expect, test } from "@playwright/test"

import type { AuthClient } from "../src/client/client.ts"

type Win = {
  auth: AuthClient
  outcome?: { status: string } | { error: string }
}

const origin = "http://auth.test"
const dist = path.resolve(import.meta.dirname, "../dist")

for (const restoreFirst of [true, false]) {
  test(`passwordless confirmation survives cold restore (restore first: ${restoreFirst})`, async ({
    page,
    context,
  }) => {
    let releaseRestore!: () => void
    let releaseConfirmation!: () => void
    const restoreGate = new Promise<void>((resolve) => {
      releaseRestore = resolve
    })
    const confirmationGate = new Promise<void>((resolve) => {
      releaseConfirmation = resolve
    })
    let restores = 0
    let confirmations = 0
    let profileCookie = ""
    const token = `h.${Buffer.from(JSON.stringify({ sub: "A", exp: 9_999_999_999 })).toString("base64url")}.s`
    await context.addCookies([
      { name: "authkit_rt_test", value: "stale", url: origin, httpOnly: true },
    ])
    await page.route(`${origin}/**`, async (route) => {
      const pathname = new URL(route.request().url()).pathname
      if (pathname.startsWith("/__auth-ui/")) {
        await route.fulfill({
          path: path.join(dist, pathname.slice("/__auth-ui/".length)),
          contentType: "text/javascript",
        })
      } else if (pathname === "/api/v1/token") {
        restores++
        await restoreGate
        // The real no-session/invalid-refresh handler sends no Set-Cookie.
        await route.fulfill({
          status: 401,
          json: { error: { code: "no_session", message: "no_session" } },
        })
      } else if (pathname === "/api/v1/passwordless/confirm") {
        confirmations++
        await confirmationGate
        await route.fulfill({
          status: 200,
          headers: {
            "Set-Cookie":
              "authkit_rt_test=fresh; Path=/; HttpOnly; SameSite=Lax",
          },
          json: {
            status: "complete",
            token_set: {
              access_token: token,
              token_type: "Bearer",
              expires_in: 900,
              refresh_token: null,
            },
          },
        })
      } else if (pathname === "/api/v1/me") {
        profileCookie = (await route.request().allHeaders()).cookie ?? ""
        await route.fulfill({
          status: 200,
          json: { id: "A", username: "reader" },
        })
      } else {
        await route.fulfill({
          contentType: "text/html",
          body: "<!doctype html><title>AuthKit race fixture</title>",
        })
      }
    })
    try {
      await page.goto(origin)
      const restored = page.waitForResponse(
        (response) => new URL(response.url()).pathname === "/api/v1/token"
      )
      await page.evaluate(async () => {
        const mod = await import(/* @vite-ignore */ "/__auth-ui/client.js")
        const w = window as unknown as Win
        w.auth = mod.createAuthClient({ sessionHint: false })
        w.auth.start()
        void w.auth.confirmPasswordless({ token: "test-email-link" }).then(
          (result) => {
            w.outcome = { status: result.status }
          },
          (err: Error) => {
            w.outcome = { error: err.message }
          }
        )
      })
      await expect.poll(() => restores).toBe(1)
      await expect.poll(() => confirmations).toBe(1)
      if (restoreFirst) {
        releaseRestore()
        await expect
          .poll(() =>
            page.evaluate(
              () => (window as unknown as Win).auth.getSnapshot().status
            )
          )
          .toBe("anonymous")
        releaseConfirmation()
      } else {
        releaseConfirmation()
        await expect
          .poll(() =>
            page.evaluate(
              () => (window as unknown as Win).auth.getSnapshot().status
            )
          )
          .toBe("authenticated")
        releaseRestore()
      }
      await (await restored).finished()
      await expect
        .poll(() => page.evaluate(() => (window as unknown as Win).outcome))
        .toEqual({ status: "complete" })
      expect(
        await page.evaluate(() => (window as unknown as Win).auth.getMe())
      ).toMatchObject({ id: "A" })
      expect(profileCookie).toContain("authkit_rt_test=fresh")
      expect(
        (await context.cookies()).find(
          (cookie) => cookie.name === "authkit_rt_test"
        )?.value
      ).toBe("fresh")
      expect(confirmations).toBe(1)
    } finally {
      releaseRestore()
      releaseConfirmation()
    }
  })
}
