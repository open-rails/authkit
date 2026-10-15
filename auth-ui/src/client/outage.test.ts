// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { memoryStorage } from "./testing-storage.ts"
import { authError, complete, deferred, json, jwt, tokens } from "./testing.ts"

const KEY = "authkit:session:/api/v1"

afterEach(() => {
  vi.useRealTimers()
})

describe("session recovery during outages", () => {
  it.each([
    ["network failure", () => Promise.reject(new TypeError("Failed to fetch"))],
    [
      "timeout",
      () => Promise.reject(new DOMException("Timed out", "TimeoutError")),
    ],
    ["server error", () => Promise.resolve(authError(500, "internal_error"))],
    [
      "gateway error",
      () => Promise.resolve(new Response(null, { status: 503 })),
    ],
    [
      "unrecognized 401",
      () => Promise.resolve(new Response(null, { status: 401 })),
    ],
    [
      "unrecognized 403",
      () => Promise.resolve(new Response(null, { status: 403 })),
    ],
    ["malformed success", () => Promise.resolve(json(200, {}))],
  ])(
    "keeps the hinted account through %s and retries restore",
    async (_, fail) => {
      vi.useFakeTimers()
      const hints = memoryStorage()
      hints.setItem(
        KEY,
        JSON.stringify({
          userId: "u1",
          username: "ann",
          expiresAt: Date.now() + 60_000,
        })
      )
      let refreshToken: string | null = "refresh-original"
      const fetch = vi
        .fn()
        .mockImplementationOnce(fail)
        .mockImplementationOnce(() => tokens("u1"))
      const client = createAuthClient({
        fetch,
        sessionHint: { storage: hints },
        storage: {
          get: () => refreshToken,
          set: (value) => {
            refreshToken = value
          },
        },
      })
      const changed = vi.fn()
      client.subscribe(changed)
      const stop = client.start()
      const ready = vi.fn()
      void client.ready().then(ready)
      await vi.advanceTimersByTimeAsync(0)
      expect(client.getSnapshot()).toMatchObject({
        status: "loading",
        hint: { userId: "u1", username: "ann" },
      })
      expect(refreshToken).toBe("refresh-original")
      expect(hints.getItem(KEY)).not.toBeNull()
      expect(changed).not.toHaveBeenCalled()
      expect(ready).not.toHaveBeenCalled()

      await vi.advanceTimersByTimeAsync(5_000)
      expect(fetch).toHaveBeenCalledTimes(2)
      expect(client.getSnapshot()).toMatchObject({
        status: "authenticated",
        userId: "u1",
      })
      expect(ready).toHaveBeenCalledOnce()
      stop()
    }
  )

  it("keeps an unknown cold start pending until the server confirms no session", async () => {
    vi.useFakeTimers()
    const fetch = vi
      .fn()
      .mockImplementationOnce(() => new Response(null, { status: 502 }))
      .mockImplementationOnce(() => authError(401, "no_session"))
    const client = createAuthClient({ fetch, sessionHint: false })
    const stop = client.start()
    await vi.advanceTimersByTimeAsync(0)
    expect(client.getSnapshot()).toEqual({ status: "loading" })
    await vi.advanceTimersByTimeAsync(5_000)
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "initial",
    })
    expect(vi.getTimerCount()).toBe(0)
    stop()
  })

  it("retains an expired access token and refresh credential until an authoritative refusal", async () => {
    vi.useFakeTimers({ now: 0 })
    const hints = memoryStorage()
    let refreshToken: string | null = "refresh-original"
    const fetch = vi
      .fn()
      .mockImplementationOnce(() => authError(503, "server_busy"))
      .mockImplementationOnce(() => authError(401, "invalid_token"))
    const client = createAuthClient({
      fetch,
      sessionHint: { storage: hints },
      storage: {
        get: () => refreshToken,
        set: (value) => {
          refreshToken = value
        },
      },
    })
    await client.completeSignIn(async () => complete("u1", 1))
    vi.setSystemTime(2_000)
    expect(await client.refresh()).toBe(false)
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
    expect(client.getAccessToken()).toBe(jwt("u1", 1))
    expect(refreshToken).toBe("refresh-original")
    vi.setSystemTime(7_000)
    expect(await client.refresh()).toBe(false)
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "expired",
    })
    expect(refreshToken).toBeNull()
    expect(hints.getItem(KEY)).toBeNull()
  })

  it("honors another tab's logout while a restore is stalled", async () => {
    const hints = memoryStorage()
    hints.setItem(
      KEY,
      JSON.stringify({ userId: "u1", expiresAt: Date.now() + 60_000 })
    )
    const pending = deferred<Response>()
    const client = createAuthClient({
      fetch: vi.fn(() => pending.promise),
      sessionHint: { storage: hints },
    })
    const stop = client.start()
    hints.removeItem(KEY)
    window.dispatchEvent(new StorageEvent("storage", { key: KEY }))
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
    pending.resolve(tokens("u1"))
    await client.ready()
    await Promise.resolve()
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
    stop()
  })

  it("honors explicit logout while offline", async () => {
    const hints = memoryStorage()
    const client = createAuthClient({
      fetch: vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
      sessionHint: { storage: hints },
    })
    await client.completeSignIn(async () => complete("u1"))
    expect(await client.refresh()).toBe(false)
    await client.signOut()
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
    expect(hints.getItem(KEY)).toBeNull()
  })
})
