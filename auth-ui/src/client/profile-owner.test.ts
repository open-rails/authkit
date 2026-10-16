import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import {
  complete,
  deferred,
  json,
  stubFetch,
  tokenSet,
  tokens,
} from "./testing.ts"

describe("account-bound profile update", () => {
  it("checks the expected account after a ready microtask, before capturing its bearer", async () => {
    const fetch = vi.fn()
    const client = createAuthClient({ fetch, sessionHint: false })
    await client.completeSignIn(async () => complete("A"))
    const switching = client.completeSignIn(async () => complete("B"))
    expect(client.getSnapshot()).toMatchObject({ userId: "A" })
    const saving = client.updateProfile({
      preferredLanguage: "ja",
      expectedUserId: "A",
    })
    const rejected = expect(saving).rejects.toBeInstanceOf(
      AuthSessionChangedError
    )
    await switching
    await rejected
    expect(fetch).not.toHaveBeenCalled()
  })

  it("refuses an account restored while the update waits for ready", async () => {
    const restoring = deferred<Response>()
    const fetch = stubFetch({ "POST /api/v1/token": () => restoring.promise })
    const client = createAuthClient({ fetch, sessionHint: false })
    const stop = client.start()
    try {
      const saving = client.updateProfile({
        preferredLanguage: "ja",
        expectedUserId: "A",
      })
      const rejected = expect(saving).rejects.toBeInstanceOf(
        AuthSessionChangedError
      )
      restoring.resolve(tokens("B"))
      await rejected
      expect(fetch).toHaveBeenCalledTimes(1)
      expect(fetch.mock.calls[0][0]).toBe("/api/v1/token")
    } finally {
      stop()
    }
  })

  it("sends the profile change to the expected account without serializing the guard", async () => {
    let sent: { body: unknown; authorization: string | null } | undefined
    const client = createAuthClient({
      sessionHint: false,
      fetch: stubFetch({
        "PATCH /api/v1/me": (input) => {
          sent = {
            body: JSON.parse(String(input.body)),
            authorization: new Headers(input.headers).get("Authorization"),
          }
          return json(200, {
            id: "A",
            username: "alpha",
            preferred_language: "ja",
          })
        },
      }),
    })
    await client.completeSignIn(async () => complete("A"))
    await client.updateProfile({ preferredLanguage: "ja", expectedUserId: "A" })
    expect(sent).toEqual({
      body: { preferred_language: "ja" },
      authorization: `Bearer ${tokenSet("A").access_token}`,
    })
  })
})
