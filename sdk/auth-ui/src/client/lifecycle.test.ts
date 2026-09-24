// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthKitError } from "./errors.ts"
import { authError, json, jwt, stubFetch, tokens } from "./testing.ts"
import { memoryStorage } from "./testing-storage.ts"

const KEY = "authkit:session:/api/v1"

afterEach(() => {
  vi.unstubAllGlobals()
})

const otherTab = (storage: Storage, hint: Record<string, unknown> | null) => {
  if (hint) storage.setItem(KEY, JSON.stringify(hint))
  else storage.removeItem(KEY)
  window.dispatchEvent(new StorageEvent("storage", { key: KEY }))
}

describe("session hint", () => {
  it("persists only a non-secret hint and restores into it", async () => {
    const storage = memoryStorage()
    const client = createAuthClient({
      fetch: vi.fn().mockResolvedValue(tokens("u1")),
      sessionHint: { storage },
    })
    expect(await client.refresh()).toBe(true)
    const raw = storage.getItem(KEY) ?? ""
    expect(JSON.parse(raw)).toMatchObject({ userId: "u1" })
    expect(raw).not.toContain(jwt("u1").split(".")[1])

    const reloaded = createAuthClient({
      fetch: vi.fn(),
      sessionHint: { storage },
    })
    expect(reloaded.getSnapshot()).toMatchObject({
      status: "loading",
      hint: { userId: "u1" },
    })
  })

  it("ignores an expired hint and drops one a cold restore disproves", async () => {
    const storage = memoryStorage()
    storage.setItem(KEY, JSON.stringify({ userId: "u1", expiresAt: 1 }))
    expect(
      createAuthClient({
        fetch: vi.fn(),
        sessionHint: { storage },
      }).getSnapshot()
    ).toEqual({ status: "loading" })

    storage.setItem(
      KEY,
      JSON.stringify({ userId: "u1", expiresAt: Date.now() + 60_000 })
    )
    const client = createAuthClient({
      fetch: vi.fn().mockResolvedValue(authError(401, "invalid_refresh_token")),
      sessionHint: { storage },
    })
    const stop = client.start()
    await vi.waitFor(() =>
      expect(client.getSnapshot()).toMatchObject({ status: "anonymous" })
    )
    stop()
    expect(storage.getItem(KEY)).toBeNull()
  })

  it("follows sign-out, sign-in and user switches in other tabs", async () => {
    const storage = memoryStorage()
    const fetch = stubFetch({
      "POST /api/v1/token": [tokens("u2")],
    })
    const client = createAuthClient({ fetch, sessionHint: { storage } })
    await client.completeSignIn(async () => ({ access_token: jwt("u1") }))
    const stop = client.start()

    otherTab(storage, { userId: "u1", expiresAt: Date.now() + 60_000 })
    expect(fetch).not.toHaveBeenCalled()
    expect(client.getSnapshot()).toMatchObject({ userId: "u1" })

    otherTab(storage, null)
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
    expect(fetch).not.toHaveBeenCalled()

    otherTab(storage, { userId: "u2", expiresAt: Date.now() + 60_000 })
    await vi.waitFor(() =>
      expect(client.getSnapshot()).toMatchObject({
        status: "authenticated",
        userId: "u2",
      })
    )
    stop()
  })

  it("signing out removes the hint", async () => {
    const storage = memoryStorage()
    const client = createAuthClient({
      fetch: vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
      sessionHint: { storage },
    })
    await client.completeSignIn(async () => ({ access_token: jwt("u1") }))
    expect(storage.getItem(KEY)).not.toBeNull()
    await client.signOut()
    expect(storage.getItem(KEY)).toBeNull()
  })
})

describe("contact proof", () => {
  const unproven = () =>
    authError(403, "verification_required", {
      identifier: "a@x.test",
      channel: "email",
      reason: "contact_unproven",
    })

  it("asks the handler, then retries the refused request once", async () => {
    const fetch = stubFetch({
      "POST /api/v1/user/2fa": [unproven(), json(200, { ok: true })],
      "POST /host/thing": [unproven(), json(200, { host: true })],
    })
    const client = createAuthClient({ fetch, sessionHint: false })
    await client.completeSignIn(async () => ({ access_token: jwt("u1") }))
    const prove = vi.fn().mockResolvedValue(true)
    const off = client.onContactProofRequired(prove)

    expect(
      await client.request("POST", "/user/2fa", { body: { method: "totp" } })
    ).toEqual({ ok: true })
    expect(prove).toHaveBeenCalledWith({
      identifier: "a@x.test",
      channel: "email",
    })
    const res = await client.authFetch("/host/thing", { method: "POST" })
    expect(await res.json()).toEqual({ host: true })
    expect(prove).toHaveBeenCalledTimes(2)
    off()
  })

  it("surfaces the refusal when the user declines or no handler is set", async () => {
    const fetch = stubFetch({
      "POST /api/v1/user/2fa": [unproven(), unproven()],
    })
    const client = createAuthClient({ fetch, sessionHint: false })
    await client.completeSignIn(async () => ({ access_token: jwt("u1") }))
    const off = client.onContactProofRequired(async () => false)
    await expect(client.request("POST", "/user/2fa")).rejects.toBeInstanceOf(
      AuthKitError
    )
    off()
    await expect(client.request("POST", "/user/2fa")).rejects.toMatchObject({
      code: "verification_required",
    })
  })
})

describe("restore", () => {
  it("holds requests made while restoring until the session is back", async () => {
    const fetch = stubFetch({
      "POST /api/v1/token": [tokens("u1")],
      "GET /host/thing": ({ headers }) =>
        json(200, { auth: new Headers(headers).get("Authorization") }),
    })
    const client = createAuthClient({ fetch, sessionHint: false })
    const stop = client.start()
    const res = await client.authFetch("/host/thing")
    expect(await res.json()).toEqual({ auth: `Bearer ${jwt("u1")}` })
    await client.ready()
    stop()
  })
})
