// Session-generation races.
import { expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import { memoryStorage } from "./testing-storage.ts"
import {
  authError,
  complete,
  deferred,
  json,
  jwt,
  stubFetch,
  tokens,
} from "./testing.ts"

it.each([true, false])(
  "accepts passwordless confirmation across a refused cold restore (restore first: %s)",
  async (restoreFirst) => {
    const restoring = deferred<Response>()
    const confirming = deferred<Response>()
    const fetch = stubFetch({
      "POST /api/v1/token": () => restoring.promise,
      "POST /api/v1/passwordless/confirm": () => confirming.promise,
      "GET /api/v1/me": () => json(200, { id: "A", username: "reader" }),
    })
    const client = createAuthClient({ fetch, sessionHint: false })
    const stop = client.start()
    const initialRestore = client.refresh()
    try {
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
      const confirmation = client.confirmPasswordless({ token: "email-link" })
      const accepted = expect(confirmation).resolves.toMatchObject({
        status: "complete",
      })
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
      if (restoreFirst) {
        restoring.resolve(authError(401, "no_session"))
        await client.ready()
      }
      confirming.resolve(tokens("A"))
      await accepted
      if (!restoreFirst) {
        restoring.resolve(authError(401, "no_session"))
        await initialRestore
      }
      expect(await client.getMe()).toMatchObject({ id: "A" })
      expect(client.getSnapshot()).toMatchObject({
        status: "authenticated",
        userId: "A",
      })
      expect(fetch).toHaveBeenCalledTimes(3)
    } finally {
      stop()
    }
  }
)

it.each(["logout", "replacement"] as const)(
  "a %s still invalidates passwordless confirmation during cold restore",
  async (interruption) => {
    const restoring = deferred<Response>()
    const confirming = deferred<Response>()
    const fetch = stubFetch({
      "POST /api/v1/token": () => restoring.promise,
      "POST /api/v1/passwordless/confirm": () => confirming.promise,
    })
    const client = createAuthClient({ fetch, sessionHint: false })
    const stop = client.start()
    try {
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
      const confirmation = client.confirmPasswordless({ token: "email-link" })
      const rejected = expect(confirmation).rejects.toBeInstanceOf(
        AuthSessionChangedError
      )
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(2))
      if (interruption === "logout") await client.signOut()
      else await client.completeSignIn(async () => complete("B"))
      restoring.resolve(authError(401, "no_session"))
      confirming.resolve(tokens("A"))
      await rejected
      expect(userId(client)).toBe(interruption === "logout" ? null : "B")
    } finally {
      stop()
    }
  }
)

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

it.each(["authkit", "host"] as const)(
  "%s does not adopt another account while awaiting readiness",
  async (transport) => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    const client = await signedIn(fetch, "A")
    // Queue B's commit ahead of the request's resolved ready() continuation.
    const replacement = login(client, "B")
    expect(userId(client)).toBe("A")
    const request =
      transport === "host"
        ? client.authFetch("/host/settings", { method: "PUT" })
        : client.request("PUT", "/me/preferences", { body: { value: "A" } })
    const rejected = expect(request).rejects.toBeInstanceOf(
      AuthSessionChangedError
    )
    await replacement
    await rejected
    expect(fetch).not.toHaveBeenCalled()
    expect(userId(client)).toBe("B")
  }
)

it.each(["authkit", "host"] as const)(
  "%s accepts its initial cookie restore with or without an account hint",
  async (transport) => {
    for (const hinted of [true, false]) {
      const restoring = deferred<Response>()
      const storage = memoryStorage()
      if (hinted)
        storage.setItem(
          "authkit:session:/api/v1",
          JSON.stringify({ userId: "A", expiresAt: Date.now() + 60_000 })
        )
      const fetch = stubFetch({
        "POST /api/v1/token": () => restoring.promise,
        "GET /api/v1/me/preferences": ({ headers }) =>
          json(200, {
            authorization: new Headers(headers).get("Authorization"),
          }),
        "GET /host/settings": ({ headers }) =>
          json(200, {
            authorization: new Headers(headers).get("Authorization"),
          }),
      })
      const client = createAuthClient({ fetch, sessionHint: { storage } })
      const stop = client.start()
      try {
        const request =
          transport === "host"
            ? client.authFetch("/host/settings").then((r) => r.json())
            : client.request("GET", "/me/preferences")
        expect(fetch).toHaveBeenCalledTimes(1)
        restoring.resolve(tokens("A"))
        await expect(request).resolves.toEqual({
          authorization: `Bearer ${jwt("A")}`,
        })
        expect(fetch).toHaveBeenCalledTimes(2)
      } finally {
        stop()
      }
    }
  }
)

it.each(["authkit", "host"] as const)(
  "%s refuses a different account restored under the original account hint",
  async (transport) => {
    const restoring = deferred<Response>()
    const storage = memoryStorage()
    storage.setItem(
      "authkit:session:/api/v1",
      JSON.stringify({ userId: "A", expiresAt: Date.now() + 60_000 })
    )
    const fetch = vi
      .fn()
      .mockImplementation((input: RequestInfo | URL) =>
        String(input).endsWith("/token")
          ? restoring.promise
          : Promise.resolve(json(200, {}))
      )
    const client = createAuthClient({ fetch, sessionHint: { storage } })
    const stop = client.start()
    try {
      const request =
        transport === "host"
          ? client.authFetch("/host/settings", { method: "PUT" })
          : client.request("PUT", "/me/preferences", { body: { value: "A" } })
      const rejected = expect(request).rejects.toBeInstanceOf(
        AuthSessionChangedError
      )
      restoring.resolve(tokens("B"))
      await rejected
      expect(fetch).toHaveBeenCalledTimes(1)
      expect(userId(client)).toBe("B")
    } finally {
      stop()
    }
  }
)

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

it("a refresh minting a different subject is discarded", async () => {
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

it("rejects a profile for a different subject without a generation change", async () => {
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
