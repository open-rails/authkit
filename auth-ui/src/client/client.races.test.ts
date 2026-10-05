// Session-generation races.
import { expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import { authError, complete, deferred, json, tokens } from "./testing.ts"

const signedIn = async (fetch: typeof globalThis.fetch, sub: string) => {
  const client = createAuthClient({ fetch })
  await client.completeSignIn(async () => complete(sub))
  return client
}

const login = (client: ReturnType<typeof createAuthClient>, sub: string) =>
  client.completeSignIn(async () => complete(sub))

const userId = (client: ReturnType<typeof createAuthClient>) => {
  const s = client.getSnapshot()
  return s.status === "authenticated" ? s.userId : null
}

it.each([
  ["authkit", 401],
  ["host", 401],
  ["authkit", 403],
  ["host", 403],
] as const)(
  "%s mutations do not retry a %i refusal under a replacement session",
  async (transport, status) => {
    const pending = deferred<Response>()
    const fetch = vi
      .fn()
      .mockReturnValueOnce(pending.promise)
      .mockImplementation(async (url: RequestInfo | URL) =>
        String(url).endsWith("/token")
          ? tokens("B")
          : new Response(null, { status: 204 })
      )
    const client = await signedIn(fetch, "A")
    const prove = vi.fn().mockResolvedValue(true)
    client.onContactProofRequired(prove)
    const changing =
      transport === "authkit"
        ? client.changeEmail("a-new@example.test")
        : client.authFetch("/host/settings", { method: "PUT" })
    const rejected = expect(changing).rejects.toBeInstanceOf(
      AuthSessionChangedError
    )
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    await login(client, "B")
    pending.resolve(
      status === 401
        ? authError(401, "token_expired")
        : authError(403, "verification_required", {
            identifier: "a@example.test",
            channel: "email",
            reason: "contact_unproven",
          })
    )
    await rejected
    expect(fetch).toHaveBeenCalledOnce()
    expect(prove).not.toHaveBeenCalled()
    expect(userId(client)).toBe("B")
  }
)

it.each(["authkit", "host"] as const)(
  "%s mutations recheck the session after refresh completes",
  async (transport) => {
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(authError(401, "token_expired"))
      .mockResolvedValueOnce(tokens("A", 9_999_999_998))
    const client = await signedIn(fetch, "A")
    const off = client.subscribe(() => {
      off()
      void login(client, "B")
    })
    const changing =
      transport === "authkit"
        ? client.changeEmail("a-new@example.test")
        : client.authFetch("/host/settings", { method: "PUT" })
    await expect(changing).rejects.toBeInstanceOf(AuthSessionChangedError)
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(userId(client)).toBe("B")
  }
)

it.each(["authkit", "host"] as const)(
  "%s contact-proof retries stay bound to their session while allowing token rotation",
  async (transport) => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        authError(403, "verification_required", {
          identifier: "a@example.test",
          channel: "email",
          reason: "contact_unproven",
        })
      )
      .mockResolvedValueOnce(tokens("A", 9_999_999_998))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    const client = await signedIn(fetch, "A")
    client.onContactProofRequired(async () => client.refresh())
    if (transport === "authkit") await client.changeEmail("a-new@example.test")
    else await client.authFetch("/host/settings", { method: "PUT" })
    expect(fetch).toHaveBeenCalledTimes(3)
    expect(
      new Headers(fetch.mock.calls[2][1]?.headers).get("Authorization")
    ).toBe(`Bearer ${client.getAccessToken()}`)
    expect(userId(client)).toBe("A")
  }
)

it.each(["authkit", "host"] as const)(
  "%s mutations do not retry after the account changes during contact proof",
  async (transport) => {
    const proof = deferred<boolean>()
    const fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        authError(403, "verification_required", {
          identifier: "a@example.test",
          channel: "email",
          reason: "contact_unproven",
        })
      )
    const client = await signedIn(fetch, "A")
    const prove = vi.fn(() => proof.promise)
    client.onContactProofRequired(prove)
    const changing =
      transport === "authkit"
        ? client.changeEmail("a-new@example.test")
        : client.authFetch("/host/settings", { method: "PUT" })
    const rejected = expect(changing).rejects.toBeInstanceOf(
      AuthSessionChangedError
    )
    await vi.waitFor(() => expect(prove).toHaveBeenCalledOnce())
    await login(client, "B")
    proof.resolve(true)
    await rejected
    expect(fetch).toHaveBeenCalledOnce()
    expect(userId(client)).toBe("B")
  }
)

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
        : json(status, { error: { code: "invalid_token" } })
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
  body.resolve(complete("A"))
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
  body.resolve(complete("A"))
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
