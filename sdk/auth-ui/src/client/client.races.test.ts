// Session-generation races ported from the doujins AuthSDK suite.
import { expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import { deferred, json, jwt, tokens } from "./testing.ts"

const signedIn = async (fetch: typeof globalThis.fetch, sub: string) => {
  const client = createAuthClient({ fetch })
  await client.completeSignIn(async () => ({ access_token: jwt(sub) }))
  return client
}

const login = (client: ReturnType<typeof createAuthClient>, sub: string) =>
  client.completeSignIn(async () => ({ access_token: jwt(sub) }))

const userId = (client: ReturnType<typeof createAuthClient>) => {
  const s = client.getSnapshot()
  return s.status === "authenticated" ? s.userId : null
}

it.each([false, true])(
  "discards a refresh that lands after logout (cold boot=%s)",
  async (cold) => {
    const pending = deferred<Response>()
    const fetch = vi.fn((url: RequestInfo | URL) =>
      String(url).endsWith("/token")
        ? pending.promise
        : Promise.resolve(new Response(null, { status: 204 }))
    )
    const client = cold
      ? createAuthClient({ fetch })
      : await signedIn(fetch, "A")
    const refreshing = client.refresh()
    const logout = client.signOut()
    expect(client.getAccessToken()).toBeNull()
    pending.resolve(tokens("A"))
    expect(await refreshing).toBe(false)
    await logout
    expect(client.getAccessToken()).toBeNull()
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
  }
)

it.each([200, 401, 403])(
  "an old refresh answering %s cannot replace or clear the new account",
  async (status) => {
    const pending = deferred<Response>()
    const client = await signedIn(vi.fn().mockReturnValue(pending.promise), "A")
    const refreshing = client.refresh()
    await login(client, "B")
    pending.resolve(
      status === 200
        ? tokens("A")
        : json(status, { error: { code: "invalid_refresh_token" } })
    )
    expect(await refreshing).toBe(false)
    expect(userId(client)).toBe("B")
  }
)

it("checks ownership after a delayed JSON body, not only after headers", async () => {
  const body = deferred<unknown>()
  const read = vi.fn(() => body.promise)
  const client = await signedIn(
    vi.fn().mockResolvedValue({ ok: true, status: 200, json: read }),
    "A"
  )
  const refreshing = client.refresh()
  await vi.waitFor(() => expect(read).toHaveBeenCalled())
  await login(client, "B")
  body.resolve({ access_token: jwt("A") })
  expect(await refreshing).toBe(false)
  expect(userId(client)).toBe("B")
})

it("a refresh minting a different principal is discarded", async () => {
  const client = await signedIn(vi.fn().mockResolvedValue(tokens("Z")), "A")
  expect(await client.refresh()).toBe(false)
  expect(userId(client)).toBe("A")
})

it("single-flights within a generation without joining another generation's refresh", async () => {
  const a = deferred<Response>()
  const b = deferred<Response>()
  const fetch = vi
    .fn()
    .mockReturnValueOnce(a.promise)
    .mockReturnValueOnce(b.promise)
  const client = await signedIn(fetch, "A")
  const old = client.refresh()
  const oldJoined = client.refresh()
  expect(fetch).toHaveBeenCalledTimes(1)
  await login(client, "B")
  const current = client.refresh()
  expect(fetch).toHaveBeenCalledTimes(2)
  a.resolve(tokens("A"))
  expect(await old).toBe(false)
  expect(await oldJoined).toBe(false)
  const joined = client.refresh()
  expect(fetch).toHaveBeenCalledTimes(2)
  b.resolve(tokens("B"))
  expect(await current).toBe(true)
  expect(await joined).toBe(true)
  expect(userId(client)).toBe("B")
})

it("a late logout response cannot clear a replacement login", async () => {
  const pending = deferred<Response>()
  const client = await signedIn(vi.fn().mockReturnValue(pending.promise), "A")
  const logout = client.signOut()
  expect(client.getAccessToken()).toBeNull()
  await login(client, "B")
  pending.resolve(new Response(null, { status: 204 }))
  await logout
  expect(userId(client)).toBe("B")
})

it("a sign-in whose session was signed out mid-flight is rejected", async () => {
  const client = createAuthClient({
    fetch: vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
  })
  const body = deferred<unknown>()
  const signingIn = client.completeSignIn(() => body.promise)
  await client.signOut()
  body.resolve({ access_token: jwt("A") })
  await expect(signingIn).rejects.toBeInstanceOf(AuthSessionChangedError)
  expect(client.getAccessToken()).toBeNull()
})

it("does not return an old profile after account replacement", async () => {
  const pending = deferred<Response>()
  const client = await signedIn(vi.fn().mockReturnValue(pending.promise), "A")
  const fetching = client.getMe()
  await login(client, "B")
  pending.resolve(json(200, { id: "A" }))
  expect(await fetching).toBeNull()
  expect(userId(client)).toBe("B")
})

it("rejects a profile for a different principal without a generation change", async () => {
  const client = await signedIn(
    vi.fn().mockResolvedValue(json(200, { id: "A" })),
    "B"
  )
  expect(await client.getMe()).toBeNull()
})

it("checks profile ownership again after its body resolves", async () => {
  const body = deferred<string>()
  const text = vi.fn(() => body.promise)
  const client = await signedIn(
    vi.fn().mockResolvedValue({ ok: true, status: 200, text }),
    "A"
  )
  const fetching = client.getMe()
  await vi.waitFor(() => expect(text).toHaveBeenCalledOnce())
  await login(client, "B")
  body.resolve(JSON.stringify({ id: "A" }))
  expect(await fetching).toBeNull()
})

it("holds a sign-in until the previous logout answered", async () => {
  // The logout response clears the refresh cookie; a login answered before it
  // would lose its fresh cookie.
  const logout = deferred<Response>()
  const order: string[] = []
  const fetch = vi.fn((url: RequestInfo | URL) => {
    const path = new URL(String(url), "http://x").pathname
    order.push(path)
    return path.endsWith("/logout")
      ? logout.promise
      : Promise.resolve(tokens("B"))
  })
  const client = await signedIn(fetch, "A")
  const out = client.signOut()
  const signIn = client.signInWithPassword({ identifier: "b", password: "pw" })
  await Promise.resolve()
  expect(order).toEqual(["/api/v1/logout"])
  logout.resolve(new Response(null, { status: 204 }))
  await out
  await signIn
  expect(order).toEqual(["/api/v1/logout", "/api/v1/password/login"])
  expect(userId(client)).toBe("B")
})
