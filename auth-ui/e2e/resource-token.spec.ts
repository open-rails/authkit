import path from "node:path"

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test"

import type { AuthClient } from "../src/client/index.ts"
import { outbox } from "./support/api"

type Mod = typeof import("../src/client/index.ts")
type Win = { auth: AuthClient; mod: Mod }

const dist = path.resolve(import.meta.dirname, "../dist")
const keyName = "authkit:resource:e2e-host"

// Installs the built client as window.auth, with resource tokens through
// the harness's token-exchange client, and restores the session. dpop binds
// the session itself (createAuthClient's dpop).
async function loadClient(page: Page, dpop = false) {
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
  await page.evaluate(async (dpop) => {
    const w = window as unknown as Win
    w.mod = await import(/* @vite-ignore */ "/__auth-ui/client.js")
    w.auth = w.mod.createAuthClient({
      dpop,
      resourceTokens: { clientId: "e2e-host", dpop: true },
    })
    w.auth.start()
    await w.auth.ready()
  }, dpop)
}

// Registers and signs in a new user through window.auth.
async function signUp(page: Page, request: APIRequestContext) {
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `group-${id}@example.test`
  await page.evaluate(
    (input) => (window as unknown as Win).auth.register(input),
    {
      identifier: email,
      username: `g${id}`,
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
  return { email, userId: userId! }
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

test("resource tokens bound to a group: group_id per merchant, one token per group, a bound session's own key", async ({
  page,
  request,
  baseURL,
}) => {
  const resource = `${baseURL}/__test/resource`
  await loadClient(page, true)
  const { email, userId } = await signUp(page, request)
  const group = async () => {
    const res = await request.post(
      `/__test/groups?email=${encodeURIComponent(email)}`
    )
    expect(res.status()).toBe(200)
    return ((await res.json()) as { id: string }).id
  }
  const [m1, m2] = [await group(), await group()]

  const out = await page.evaluate(
    async ({ resource, m1, m2, sessionKey }) => {
      const { auth, mod } = window as unknown as Win
      const whoami = async (group?: string) => {
        const res = await auth.resourceFetch("/__test/resource/whoami", {
          resource,
          scope: "e2e:read",
          group,
        })
        return { status: res.status, body: await res.json() }
      }
      const t1 = await auth.getResourceToken({
        resource,
        scope: "e2e:read",
        group: m1,
      })
      const t2 = await auth.getResourceToken({
        resource,
        scope: "e2e:read",
        group: m2,
      })
      const t1Again = await auth.getResourceToken({
        resource,
        scope: "e2e:read",
        group: m1,
      })
      return {
        t1,
        t2,
        cached: t1Again.accessToken === t1.accessToken,
        w1: await whoami(m1),
        w2: await whoami(m2),
        unbound: await whoami(),
        sessionJkt: (await mod.loadDPoPKey(sessionKey)).thumbprint,
      }
    },
    { resource, m1, m2, sessionKey: "authkit:session-key:/api/v1" }
  )
  expect(out.t1).toMatchObject({ tokenType: "DPoP", resource, group: m1 })
  expect(out.t2.group).toBe(m2)
  expect(out.t2.accessToken).not.toBe(out.t1.accessToken)
  expect(out.cached).toBe(true)
  // The session is DPoP-bound, so its tokens are exchanged with, and bound
  // to, its own key.
  expect(out.w1).toEqual({
    status: 200,
    body: {
      sub: userId,
      client_id: "e2e-host",
      scopes: ["e2e:read"],
      jkt: out.sessionJkt,
      group_id: m1,
    },
  })
  expect(out.w2.body).toMatchObject({ group_id: m2, jkt: out.sessionJkt })
  expect(out.unbound.status).toBe(200)
  expect(out.unbound.body).not.toHaveProperty("group_id")

  // A group the user holds no role in is refused.
  const refused = await page.evaluate(async (resource) => {
    try {
      await (window as unknown as Win).auth.getResourceToken({
        resource,
        group: "0199b1a2-7c3d-7e4f-8a9b-0c1d2e3f4a5b",
      })
      return "ok"
    } catch (e) {
      return (e as { error?: string }).error
    }
  }, resource)
  expect(refused).toBe("invalid_target")
})
