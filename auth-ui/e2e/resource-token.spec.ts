import path from "node:path"

import { expect, test, type Page } from "@playwright/test"

import type { AuthClient } from "../src/client/index.ts"
import { outbox } from "./support/api"

type Mod = typeof import("../src/client/index.ts")
type Win = { auth: AuthClient; mod: Mod }

const dist = path.resolve(import.meta.dirname, "../dist")
const keyName = "authkit:resource:e2e-host"

// Installs the built client as window.auth, with resource tokens through
// the harness's token-exchange client, and restores the session.
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
    w.mod = await import(/* @vite-ignore */ "/__auth-ui/client.js")
    w.auth = w.mod.createAuthClient({
      resourceTokens: { clientId: "e2e-host", dpop: true },
    })
    w.auth.start()
    await w.auth.ready()
  })
}

test("resource tokens: token exchange, DPoP with server nonces, a key that survives reload", async ({
  page,
  request,
  baseURL,
}) => {
  const resource = `${baseURL}/__test/resource`
  await loadClient(page)
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `resource-${id}@example.test`
  await page.evaluate(
    (input) => (window as unknown as Win).auth.register(input),
    {
      identifier: email,
      username: `r${id}`,
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
  const userId = await page.evaluate(() => {
    const s = (window as unknown as Win).auth.getSnapshot()
    return s.status === "authenticated" ? s.userId : null
  })
  expect(userId).toBeTruthy()

  const seen: { url: string; status: number; dpop: boolean; auth: string }[] =
    []
  page.on("response", (res) => {
    const req = res.request()
    if (/\/oauth2\/token|\/__test\/resource/.test(req.url()))
      seen.push({
        url: new URL(req.url()).pathname,
        status: res.status(),
        dpop: !!req.headers()["dpop"],
        auth: (req.headers()["authorization"] ?? "").split(" ")[0],
      })
  })

  const first = await page.evaluate(
    async ({ resource, keyName }) => {
      const { auth, mod } = window as unknown as Win
      const token = await auth.getResourceToken({ resource, scope: "e2e:read" })
      const again = await auth.getResourceToken({ resource, scope: "e2e:read" })
      const res = await auth.resourceFetch("/__test/resource/whoami", {
        resource,
        scope: "e2e:read",
      })
      return {
        token,
        cached: again.accessToken === token.accessToken,
        status: res.status,
        body: await res.json(),
        thumbprint: (await mod.loadDPoPKey(keyName)).thumbprint,
      }
    },
    { resource, keyName }
  )
  expect(first.token).toMatchObject({
    tokenType: "DPoP",
    resource,
    scope: ["e2e:read"],
  })
  expect(first.cached).toBe(true)
  expect(first.status).toBe(200)
  expect(first.body).toEqual({
    sub: userId,
    client_id: "e2e-host",
    scopes: ["e2e:read"],
    jkt: first.thumbprint,
  })
  // One exchange; the resource server asked for its nonce, then accepted.
  expect(seen).toEqual([
    { url: "/oauth2/token", status: 200, dpop: true, auth: "" },
    { url: "/__test/resource/whoami", status: 401, dpop: true, auth: "DPoP" },
    { url: "/__test/resource/whoami", status: 200, dpop: true, auth: "DPoP" },
  ])

  // The token is useless without its key's proof.
  const bearer = await page.evaluate(async (token) => {
    const res = await fetch("/__test/resource/whoami", {
      headers: { Authorization: `Bearer ${token}` },
    })
    return res.status
  }, first.token.accessToken)
  expect(bearer).toBe(401)

  // After a reload the session restores and the same key binds new tokens.
  await page.reload()
  await loadClient(page)
  const second = await page.evaluate(
    async ({ resource, keyName }) => {
      const { auth, mod } = window as unknown as Win
      const res = await auth.resourceFetch("/__test/resource/whoami", {
        resource,
        scope: "e2e:read",
      })
      return {
        status: res.status,
        body: await res.json(),
        thumbprint: (await mod.loadDPoPKey(keyName)).thumbprint,
      }
    },
    { resource, keyName }
  )
  expect(second.status).toBe(200)
  expect(second.thumbprint).toBe(first.thumbprint)
  expect(second.body).toMatchObject({ sub: userId, jkt: first.thumbprint })

  // A resource the client may not reach, and a signed-out session, refuse.
  const refusals = await page.evaluate(async (base) => {
    const { auth } = window as unknown as Win
    const code = async (p: Promise<unknown>) => {
      try {
        await p
        return "ok"
      } catch (e) {
        return (
          (e as { error?: string; code?: string }).error ??
          (e as { code?: string }).code
        )
      }
    }
    const target = await code(
      auth.getResourceToken({ resource: `${base}/elsewhere` })
    )
    const scope = await code(
      auth.getResourceToken({
        resource: `${base}/__test/resource`,
        scope: "admin",
      })
    )
    await auth.signOut()
    const signedOut = await code(
      auth.getResourceToken({ resource: `${base}/__test/resource` })
    )
    return { target, scope, signedOut }
  }, baseURL)
  expect(refusals).toEqual({
    target: "invalid_target",
    scope: "invalid_scope",
    signedOut: "unauthenticated",
  })
})
