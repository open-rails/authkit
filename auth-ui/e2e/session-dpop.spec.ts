import path from "node:path"

import { expect, test, type Page } from "@playwright/test"

import type { AuthClient } from "../src/client/index.ts"
import { outbox } from "./support/api"

type Win = { auth: AuthClient }

const dist = path.resolve(import.meta.dirname, "../dist")

// Installs the built client as window.auth with DPoP-bound sessions, and
// restores the session.
async function loadClient(page: Page) {
  await page.route("**/__auth-ui/**/*.js", (route, req) =>
    route.fulfill({
      path: path.join(
        dist,
        new URL(req.url()).pathname.replace(/^\/__auth-ui\//, "")
      ),
      contentType: "text/javascript",
    })
  )
  await page.goto("/")
  await page.evaluate(async () => {
    const w = window as unknown as Win
    const mod = await import(/* @vite-ignore */ "/__auth-ui/client.js")
    w.auth = mod.createAuthClient({ dpop: true })
    w.auth.start()
    await w.auth.ready()
  })
}

test("a DPoP-bound session: bound tokens, refused as Bearer, restored after a reload", async ({
  page,
  request,
}) => {
  await loadClient(page)
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `bound-${id}@example.test`
  await page.evaluate(
    (input) => (window as unknown as Win).auth.register(input),
    {
      identifier: email,
      username: `b${id}`,
      password: "Correct-horse-battery-9",
    }
  )
  const code = (await outbox(request, email)).find(
    (m) => m.kind === "verification"
  )?.code
  await page.evaluate(
    (input) => (window as unknown as Win).auth.confirmVerification(input),
    { identifier: email, code: code! }
  )
  const first = await page.evaluate(async () => {
    const { auth } = window as unknown as Win
    const s = auth.getSnapshot()
    if (s.status !== "authenticated") return null
    const bound = await auth.authFetch("/api/v1/me")
    const bearer = await fetch("/api/v1/me", {
      headers: { Authorization: `Bearer ${s.accessToken}` },
    })
    return {
      cnf: (s.claims as Record<string, unknown>).cnf,
      bound: bound.status,
      bearer: bearer.status,
    }
  })
  expect(first).not.toBeNull()
  expect(first!.cnf).toMatchObject({ jkt: expect.any(String) })
  expect(first!.bound).toBe(200)
  expect(first!.bearer).toBe(401)

  // The refresh cookie restores the session, proving the same key.
  await page.reload()
  await loadClient(page)
  const restored = await page.evaluate(async () => {
    const { auth } = window as unknown as Win
    const s = auth.getSnapshot()
    return {
      status: s.status,
      me: (await auth.authFetch("/api/v1/me")).status,
    }
  })
  expect(restored).toEqual({ status: "authenticated", me: 200 })
})
