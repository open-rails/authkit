import { describe, expect, it, vi } from "vitest"

import { createAuthClient, type AuthClient } from "./client.ts"
import { AuthSessionChangedError } from "./errors.ts"
import {
  authResult,
  complete,
  deferred,
  json,
  stubFetch,
  tokenSet,
} from "./testing.ts"

describe("registration event", () => {
  const cases: Array<{
    name: string
    path: string
    run: (client: AuthClient) => Promise<unknown>
  }> = [
    {
      name: "native registration",
      path: "/register",
      run: (client) =>
        client.register({
          identifier: "a@b.test",
          username: "a",
          password: "p",
        }),
    },
    {
      name: "contact verification",
      path: "/verify/confirm",
      run: (client) =>
        client.confirmVerification({ identifier: "a@b.test", code: "123456" }),
    },
    {
      name: "passwordless registration",
      path: "/passwordless/confirm",
      run: (client) =>
        client.confirmPasswordless({ identifier: "a@b.test", code: "123456" }),
    },
    {
      name: "provider redirect",
      path: "/oidc/exchange",
      run: (client) =>
        client.completeRedirect("#code=one-time&state=s&provider=google"),
    },
    {
      name: "second-factor continuation",
      path: "/2fa/verify",
      run: (client) =>
        client.verifyTwoFactor({
          userId: "new-user",
          challenge: "c",
          code: "123456",
        }),
    },
    {
      name: "new-device continuation",
      path: "/device-verification/confirm",
      run: (client) =>
        client.confirmDeviceVerification({
          userId: "new-user",
          challenge: "c",
          code: "123456",
        }),
    },
  ]

  it.each(cases)(
    "reports $name before session listeners, with usable credentials",
    async ({ path, run }) => {
      const client = createAuthClient({
        sessionHint: false,
        fetch: stubFetch({
          [`POST /api/v1${path}`]: [
            json(200, complete("new-user", undefined, { created: true })),
          ],
        }),
      })
      const order: string[] = []
      const observations: unknown[] = []
      client.subscribe(() => order.push("session"))
      client.onRegistered((event) => {
        order.push("registered")
        observations.push({
          event,
          session: client.getSnapshot(),
          accessToken: client.getAccessToken(),
        })
      })
      await run(client)
      expect(order).toEqual(["registered", "session"])
      expect(observations).toEqual([
        {
          event: { userId: "new-user" },
          session: expect.objectContaining({
            status: "authenticated",
            userId: "new-user",
          }),
          accessToken: tokenSet("new-user").access_token,
        },
      ])
    }
  )

  it("uses the same completion seam as wallet sign-in, but does not emit for pending steps", async () => {
    const client = createAuthClient({ sessionHint: false })
    const registered = vi.fn()
    client.onRegistered(registered)
    await client.completeSignIn(async () =>
      authResult("enrollment_required", {
        enrollment: {
          token_set: tokenSet("new-user"),
          allowed_methods: ["totp"],
        },
      })
    )
    expect(registered).not.toHaveBeenCalled()
    await client.completeSignIn(async () =>
      complete("new-user", undefined, { created: true })
    )
    expect(registered).toHaveBeenCalledExactlyOnceWith({ userId: "new-user" })
  })

  it("reports forced enrollment completion but not an existing account adding a factor", async () => {
    const factorResult = () =>
      json(200, {
        factor: {
          id: "factor",
          method: "totp",
          is_default: true,
          destination: null,
        },
        backup_codes: [],
        auth: complete("new-user", undefined, { created: true }),
      })
    const client = createAuthClient({
      sessionHint: false,
      fetch: stubFetch({ "POST /api/v1/me/2fa/factors": () => factorResult() }),
    })
    const registered = vi.fn()
    client.onRegistered(registered)
    await client.addTwoFactorFactor(
      { method: "totp", code: "123456" },
      { enrollmentToken: tokenSet("enrollment") }
    )
    expect(registered).toHaveBeenCalledExactlyOnceWith({ userId: "new-user" })
    await client.addTwoFactorFactor({ method: "totp", code: "654321" })
    expect(registered).toHaveBeenCalledTimes(1)
  })

  it("never replays registration for refresh, existing sign-in, or provider linking", async () => {
    const client = createAuthClient({
      sessionHint: false,
      fetch: stubFetch({
        "POST /api/v1/token": [
          json(200, complete("new-user", undefined, { created: true })),
        ],
      }),
    })
    const registered = vi.fn()
    client.onRegistered(registered)
    await client.completeSignIn(async () =>
      complete("new-user", undefined, { created: true })
    )
    await client.refresh()
    await client.completeSignIn(async () => complete("existing-user"))
    await client.completeSignIn(async () => ({
      ...complete("existing-user"),
      created: "true",
    }))
    await client.completeRedirect("#flow=link&result=success&provider=google")
    expect(registered).toHaveBeenCalledExactlyOnceWith({ userId: "new-user" })
  })

  it("ignores a superseded signup and isolates failing or removed listeners", async () => {
    const client = createAuthClient({ sessionHint: false })
    const removed = vi.fn()
    client.onRegistered(removed)()
    client.onRegistered(() => {
      throw new Error("consumer failed")
    })
    const registered = vi.fn()
    client.onRegistered(registered)
    const response = deferred<unknown>()
    const pending = client.completeSignIn(() => response.promise)
    await client.completeSignIn(async () => complete("existing-user"))
    response.resolve(complete("new-user", undefined, { created: true }))
    await expect(pending).rejects.toBeInstanceOf(AuthSessionChangedError)
    expect(registered).not.toHaveBeenCalled()
    await client.completeSignIn(async () =>
      complete("new-user", undefined, { created: true })
    )
    expect(registered).toHaveBeenCalledExactlyOnceWith({ userId: "new-user" })
    expect(removed).not.toHaveBeenCalled()
  })
})
