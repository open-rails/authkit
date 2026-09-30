import { afterEach, describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthKitError } from "./errors.ts"
import {
  authError,
  authResult,
  complete,
  json,
  jwt,
  stubFetch,
  tokenSet,
  tokens,
} from "./testing.ts"

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const signIn = (
  client: ReturnType<typeof createAuthClient>,
  sub = "u1",
  exp?: number
) => client.completeSignIn(async () => complete(sub, exp))

const noContent = () => new Response(null, { status: 204 })
const accepted = () => new Response(null, { status: 202 })

const factor = {
  id: "f1",
  method: "sms",
  is_default: true,
  destination: "+1***99",
}
const secondFactor = authResult("second_factor_required", {
  second_factor: {
    user_id: "u",
    challenge: "c",
    factor,
    factors: [factor],
  },
})
const enrollment = authResult("enrollment_required", {
  enrollment: { token_set: tokenSet("e"), allowed_methods: ["totp"] },
})
const fresh = {
  last_authenticated_at: "2026-09-29T00:00:00Z",
  step_up_required_for_sensitive_actions: false,
  step_up_required_in_seconds: 300,
  auth_methods: ["pwd"],
}

describe("refresh", () => {
  it("rotates through the refresh cookie without sending token material", async () => {
    const fetch = vi.fn().mockResolvedValue(tokens("u1"))
    const client = createAuthClient({ fetch })
    expect(await client.refresh()).toBe(true)
    expect(fetch).toHaveBeenCalledWith("/api/v1/token", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ grant_type: "refresh_token" }),
    })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it("uses and rotates a body refresh token on mounts without the cookie", async () => {
    let stored: string | null = "rt-1"
    const storage = {
      get: () => stored,
      set: (v: string | null) => void (stored = v),
    }
    const fetch = stubFetch({
      "POST /auth/token": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({
          grant_type: "refresh_token",
          refresh_token: "rt-1",
        })
        return json(
          200,
          complete("u1", undefined, {
            token_set: { ...tokenSet("u1"), refresh_token: "rt-2" },
          })
        )
      },
      "DELETE /auth/logout": noContent,
    })
    const client = createAuthClient({ fetch, storage, baseUrl: "/auth/" })
    expect(await client.refresh()).toBe(true)
    expect(stored).toBe("rt-2")
    await client.signOut()
    expect(stored).toBeNull()
  })

  // A dead refresh credential ends the session; a failing server must not.
  it.each([400, 401, 403])(
    "ends a live session when refresh is rejected with %i",
    async (status) => {
      const client = createAuthClient({
        fetch: vi.fn().mockResolvedValue(authError(status, "invalid_token")),
      })
      await signIn(client)
      expect(await client.refresh()).toBe(false)
      expect(client.getSnapshot()).toEqual({
        status: "anonymous",
        reason: "expired",
        continuation: null,
      })
    }
  )

  it.each([429, 500, 503])(
    "keeps the session on a transient %i and honours Retry-After",
    async (status) => {
      const fetch = vi
        .fn()
        .mockResolvedValue(
          authError(status, "rate_limited", undefined, { "Retry-After": "30" })
        )
      const client = createAuthClient({ fetch })
      await signIn(client)
      expect(await client.refresh()).toBe(false)
      expect(await client.refresh()).toBe(false)
      expect(fetch).toHaveBeenCalledTimes(1)
      expect(client.getSnapshot().status).toBe("authenticated")
    }
  )

  it("ends the session on the next step a refresh answers", async () => {
    const fetch = vi.fn().mockResolvedValue(json(200, enrollment))
    const client = createAuthClient({ fetch })
    await signIn(client)
    expect(await client.refresh()).toBe(false)
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "expired",
      continuation: { status: "enrollment_required" },
    })
  })

  it("start() restores from the cookie, or settles anonymous", async () => {
    const ok = createAuthClient({
      fetch: vi.fn().mockResolvedValue(tokens("u1")),
    })
    expect(ok.getSnapshot()).toEqual({ status: "loading" })
    const stopOk = ok.start()
    await vi.waitFor(() =>
      expect(ok.getSnapshot().status).toBe("authenticated")
    )
    stopOk()

    const anon = createAuthClient({
      fetch: vi.fn().mockResolvedValue(authError(400, "invalid_request")),
    })
    const listener = vi.fn()
    anon.subscribe(listener)
    const stopAnon = anon.start()
    await vi.waitFor(() =>
      expect(anon.getSnapshot()).toEqual({
        status: "anonymous",
        reason: "initial",
        continuation: null,
      })
    )
    expect(listener).toHaveBeenCalled()
    stopAnon()
  })
})

describe("scheduler", () => {
  it("refreshes ahead of expiry and backs off on transient failure", async () => {
    vi.useFakeTimers({ now: 0 })
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        authError(503, "sms_unavailable", undefined, { "Retry-After": "30" })
      )
      .mockResolvedValueOnce(tokens("u1", 3600))
    const client = createAuthClient({ fetch })
    await signIn(client, "u1", 600)
    const stop = client.start()
    await vi.advanceTimersByTimeAsync(299_000)
    expect(fetch).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1_000)
    expect(fetch).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(29_000)
    expect(fetch).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      expiresAt: 3_600_000,
    })
    stop()
    expect(vi.getTimerCount()).toBe(0)
  })

  it("catches up on visibility when a throttled timer overslept", async () => {
    vi.useFakeTimers({ now: 0 })
    const doc = Object.assign(new EventTarget(), { visibilityState: "visible" })
    vi.stubGlobal("document", doc)
    const fetch = vi.fn().mockResolvedValue(tokens("u1", 7200))
    const client = createAuthClient({ fetch })
    await signIn(client, "u1", 3600)
    const stop = client.start()
    vi.setSystemTime(3_500_000)
    doc.dispatchEvent(new Event("visibilitychange"))
    await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1))
    stop()
  })
})

describe("requests", () => {
  it("refreshes and retries once when the bearer is stale", async () => {
    const seen: (string | null)[] = []
    const fetch = stubFetch({
      "GET /api/v1/me/sessions": ({ headers }) => {
        seen.push(new Headers(headers).get("Authorization"))
        return seen.length === 1
          ? authError(401, "invalid_token")
          : json(200, { data: [], next_cursor: null, total: null })
      },
      "POST /api/v1/token": () => tokens("u1"),
    })
    const client = createAuthClient({ fetch })
    await signIn(client, "u1", 100)
    expect(await client.listSessions()).toEqual([])
    expect(seen).toEqual([`Bearer ${jwt("u1", 100)}`, `Bearer ${jwt("u1")}`])
  })

  it("does not refresh on a semantic 401", async () => {
    const fetch = stubFetch({
      "POST /api/v1/me/step-up/password": [authError(401, "invalid_password")],
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    await expect(client.stepUpWithPassword("nope")).rejects.toMatchObject({
      code: "invalid_password",
    })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it("authFetch attaches the bearer and retries once after refresh", async () => {
    const fetch = stubFetch({
      "GET /host/thing": [
        new Response(null, { status: 401 }),
        new Response("ok"),
      ],
      "POST /api/v1/token": () => tokens("u1"),
    })
    const client = createAuthClient({ fetch })
    await signIn(client, "u1", 100)
    const res = await client.authFetch("/host/thing")
    expect(await res.text()).toBe("ok")
    expect(
      new Headers(fetch.mock.calls[2][1]?.headers).get("Authorization")
    ).toBe(`Bearer ${jwt("u1")}`)
  })

  it("reads public profiles without a bearer", async () => {
    const alice = {
      id: "a",
      username: "alice",
      avatar_url: null,
      created_at: "2026-09-01T00:00:00Z",
      deleted: false,
      metadata: {},
    }
    const page = (data: unknown[]) =>
      json(200, { data, next_cursor: null, total: null })
    const fetch = stubFetch({
      "GET /api/v1/users": [page([alice]), page([alice]), page([])],
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    expect(await client.getUsers(["a", "b"])).toEqual([alice])
    expect(await client.getUserByUsername("alice")).toEqual(alice)
    expect(await client.getUserByUsername("nobody")).toBeNull()
    expect(await client.getUsers([])).toEqual([])
    expect(fetch.mock.calls.map((c) => String(c[0]))).toEqual([
      "/api/v1/users?ids=a%2Cb",
      "/api/v1/users?username=alice",
      "/api/v1/users?username=nobody",
    ])
    for (const call of fetch.mock.calls)
      expect(new Headers(call[1]?.headers).get("Authorization")).toBeNull()
  })

  it("sends ?lang and leaves the default base only as a default", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValue(json(200, { external_login_providers: [] }))
    const client = createAuthClient({
      fetch,
      baseUrl: "https://auth.example/v2",
      language: () => "ja",
    })
    await client.getCapabilities()
    expect(fetch.mock.calls[0][0]).toBe(
      "https://auth.example/v2/capabilities?lang=ja"
    )
  })
})

describe("flows", () => {
  it("password login commits a complete AuthResult", async () => {
    const client = createAuthClient({
      fetch: stubFetch({ "POST /api/v1/password/login": [tokens("u1")] }),
    })
    expect(
      await client.signInWithPassword({ identifier: "a", password: "b" })
    ).toMatchObject({ status: "complete", token_set: { token_type: "Bearer" } })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it.each([
    secondFactor,
    enrollment,
    authResult("verification_required", {
      verification: { identifier: "a@b.c", channel: "email" },
    }),
    authResult("account_recovery_required", {
      recovery: { token: "r", expires_at: "x", purge_at: "y" },
    }),
  ])("password login returns $status without a session", async (step) => {
    const client = createAuthClient({
      fetch: stubFetch({ "POST /api/v1/password/login": [json(200, step)] }),
    })
    expect(
      await client.signInWithPassword({ identifier: "a", password: "b" })
    ).toEqual(step)
    expect(client.getAccessToken()).toBeNull()
  })

  it("refuses an AuthResult whose status lacks its step", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/password/login": [
          json(200, authResult("second_factor_required")),
        ],
      }),
    })
    await expect(
      client.signInWithPassword({ identifier: "a", password: "b" })
    ).rejects.toThrow("no AuthResult")
  })

  it("rethrows sign-in failures", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/password/login": [authError(401, "invalid_credentials")],
      }),
    })
    await expect(
      client.signInWithPassword({ identifier: "a", password: "b" })
    ).rejects.toBeInstanceOf(AuthKitError)
  })

  it("register sends invite_code and signs in only on 200", async () => {
    const bodies: unknown[] = []
    const answers = [accepted(), tokens("u2")]
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/register": ({ body }) => {
          bodies.push(JSON.parse(String(body)))
          return answers.shift()!
        },
      }),
    })
    const input = {
      identifier: "a@b.c",
      username: "u",
      password: "p",
      inviteCode: "inv",
    }
    expect(await client.register(input)).toBeNull()
    expect(client.getAccessToken()).toBeNull()
    expect(await client.register(input)).toMatchObject({ status: "complete" })
    expect(client.getSnapshot()).toMatchObject({ userId: "u2" })
    expect(bodies[0]).toEqual({
      identifier: "a@b.c",
      username: "u",
      password: "p",
      invite_code: "inv",
    })
  })

  it("confirmVerification tells a signed-in proof from a sign-in", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/verify/confirm": [noContent(), tokens("u3")],
      }),
    })
    expect(
      await client.confirmVerification({ identifier: "a@b.c", code: "X" })
    ).toBeNull()
    expect(await client.confirmVerification({ token: "t" })).toMatchObject({
      status: "complete",
    })
    expect(client.getSnapshot()).toMatchObject({ userId: "u3" })
  })

  it("a contact change is PUT /me/email|phone, then a signed-in proof", async () => {
    const fetch = stubFetch({
      "PUT /api/v1/me/email": [accepted()],
      "PUT /api/v1/me/phone": [accepted()],
      "DELETE /api/v1/me/phone": [noContent()],
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    await client.changeEmail("new@b.c")
    await client.changePhone("+15550100")
    await client.removePhone()
    expect(
      fetch.mock.calls.map((c) => JSON.parse(String(c[1]?.body ?? "null")))
    ).toEqual([{ email: "new@b.c" }, { phone_number: "+15550100" }, null])
  })

  it("a forced enrollment sets up and adds a factor with its token, then signs in", async () => {
    const fetch = stubFetch({
      "POST /api/v1/me/2fa/setup": [
        json(200, {
          method: "totp",
          destination: null,
          secret: "S",
          otpauth_uri: "otpauth://x",
        }),
      ],
      "POST /api/v1/me/2fa/factors": [
        json(201, {
          factor: { ...factor, method: "totp", destination: null },
          backup_codes: ["b1"],
          auth: complete("u1"),
        }),
      ],
    })
    const client = createAuthClient({ fetch })
    const enrollmentToken = tokenSet("enroll")
    expect(
      await client.setupTwoFactor({ method: "totp" }, { enrollmentToken })
    ).toMatchObject({ secret: "S", otpauth_uri: "otpauth://x" })
    const created = await client.addTwoFactorFactor(
      { method: "totp", code: "123456" },
      { enrollmentToken }
    )
    expect(created).toMatchObject({
      backup_codes: ["b1"],
      auth: { status: "complete" },
    })
    for (const call of fetch.mock.calls)
      expect(new Headers(call[1]?.headers).get("Authorization")).toBe(
        `Bearer ${enrollmentToken.access_token}`
      )
    expect(JSON.parse(String(fetch.mock.calls[1][1]?.body))).toEqual({
      method: "totp",
      code: "123456",
    })
    expect(client.getSnapshot()).toMatchObject({ userId: "u1" })
  })

  it("adding a factor while signed in adopts the re-verified token", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/me/2fa/factors": [
          json(201, {
            factor,
            backup_codes: [],
            auth: complete("u1", 5000, { fresh_auth: fresh }),
          }),
        ],
        "PATCH /api/v1/me/2fa/factors/f1": [json(200, factor)],
        "DELETE /api/v1/me/2fa/factors/f1": [noContent()],
        "DELETE /api/v1/me/2fa": [noContent()],
      }),
    })
    await signIn(client)
    await client.addTwoFactorFactor({
      method: "sms",
      code: "1",
      phoneNumber: "+1",
    })
    expect(client.getAccessToken()).toBe(jwt("u1", 5000))
    expect(await client.setDefaultTwoFactorFactor("f1")).toEqual(factor)
    await client.removeTwoFactorFactor("f1")
    await client.disableTwoFactor()
  })

  it("steps up with a sent code and adopts the fresh token", async () => {
    const fetch = stubFetch({
      "POST /api/v1/me/step-up/2fa/send": [accepted()],
      "POST /api/v1/me/step-up/2fa": [
        json(200, complete("u1", 5000, { fresh_auth: fresh })),
      ],
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    await client.sendStepUpCode({ method: "email" })
    expect(await client.stepUpWithTwoFactor({ code: "123" })).toEqual(fresh)
    expect(client.getAccessToken()).toBe(jwt("u1", 5000))
    expect(JSON.parse(String(fetch.mock.calls[0][1]?.body))).toEqual({
      method: "email",
    })
  })

  it("a password change that re-authenticated keeps the session fresh", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "PUT /api/v1/me/password": [
          noContent(),
          json(200, complete("u1", 7000, { fresh_auth: fresh })),
        ],
      }),
    })
    await signIn(client)
    await client.changePassword({ newPassword: "n" })
    expect(client.getAccessToken()).toBe(jwt("u1"))
    await client.changePassword({ currentPassword: "o", newPassword: "n" })
    expect(client.getAccessToken()).toBe(jwt("u1", 7000))
  })

  it("DELETE /me/sessions keeps this session; DELETE /me ends it", async () => {
    const fetch = stubFetch({
      "DELETE /api/v1/me/sessions": [noContent()],
      "DELETE /api/v1/me": [noContent()],
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    await client.revokeOtherSessions()
    expect(client.getSnapshot().status).toBe("authenticated")
    await client.deleteAccount()
    expect(fetch.mock.calls[1][1]?.body).toBeUndefined()
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
  })

  it("updateProfile patches /me", async () => {
    const fetch = stubFetch({
      "PATCH /api/v1/me": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({
          username: "neo",
          preferred_language: "de",
        })
        return json(200, { id: "u1", username: "neo" })
      },
    })
    const client = createAuthClient({ fetch })
    await signIn(client)
    expect(
      await client.updateProfile({ username: "neo", preferredLanguage: "de" })
    ).toMatchObject({ username: "neo" })
  })
})

describe("OIDC redirect", () => {
  const exchanging = (result: unknown) =>
    stubFetch({
      "POST /api/v1/oidc/exchange": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({ code: "one-time" })
        return json(200, result)
      },
    })

  it("builds the login URL outside the API prefix", () => {
    const client = createAuthClient({ language: () => "de" })
    expect(
      client.oidcLoginUrl("google", { returnTo: "/subscribe?plan=pro" })
    ).toBe("/oidc/google/login?return_to=%2Fsubscribe%3Fplan%3Dpro&lang=de")
    expect(
      client.oidcLoginUrl("google", { returnTo: "https://evil.example/" })
    ).toBe("/oidc/google/login?lang=de")
  })

  it("starts with an invitation by POST under the API", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/oidc/google/login/start": ({ body }) => {
          expect(JSON.parse(String(body))).toEqual({
            return_to: "/a",
            invite_code: "inv",
          })
          return json(200, { auth_url: "https://idp/x", state: "s" })
        },
      }),
    })
    expect(
      await client.oidcLoginStart("google", {
        returnTo: "/a",
        inviteCode: "inv",
      })
    ).toBe("https://idp/x")
  })

  it("trades the fragment's one-time code for the session", async () => {
    const client = createAuthClient({
      fetch: exchanging(complete("u1", undefined, { return_to: "/a" })),
    })
    const redirect = await client.completeRedirect(
      "#code=one-time&state=s&provider=google"
    )
    expect(redirect).toMatchObject({
      kind: "sign_in",
      provider: "google",
      result: { status: "complete", return_to: "/a" },
    })
    expect(client.getSnapshot()).toMatchObject({ userId: "u1" })
  })

  it("returns a pending step without a session", async () => {
    const client = createAuthClient({ fetch: exchanging(secondFactor) })
    expect(await client.completeRedirect("#code=one-time&state=s")).toEqual({
      kind: "sign_in",
      result: secondFactor,
      provider: undefined,
    })
    expect(client.getAccessToken()).toBeNull()
  })

  it("reads link results and errors, and leaves other fragments", async () => {
    const client = createAuthClient()
    expect(
      await client.completeRedirect("#flow=link&result=success&provider=apple")
    ).toEqual({ kind: "linked", provider: "apple" })
    expect(
      await client.completeRedirect(
        "#error=provider_already_linked&flow=link&provider=apple&state="
      )
    ).toEqual({
      kind: "error",
      code: "provider_already_linked",
      flow: "link",
      provider: "apple",
    })
    expect(await client.completeRedirect("#code=step-up")).toBeNull()
    expect(await client.completeRedirect("#nothing=here")).toBeNull()
  })

  it("finishes a step-up return on the same session", async () => {
    const client = createAuthClient({
      fetch: exchanging(complete("u1", 6000, { fresh_auth: fresh })),
    })
    await signIn(client)
    expect(await client.completeStepUp("#code=one-time")).toEqual(fresh)
    expect(client.getAccessToken()).toBe(jwt("u1", 6000))
    await expect(
      client.completeStepUp("#error=step_up_failed")
    ).rejects.toMatchObject({ code: "step_up_failed" })
    expect(await client.completeStepUp("#code=x&state=s")).toBeNull()
  })
})

describe("OIDC popup", () => {
  const origin = "https://app.test"

  const setup = () => {
    vi.useFakeTimers()
    const popup = { closed: false, close: vi.fn() }
    const win = Object.assign(new EventTarget(), {
      location: { origin, href: `${origin}/` },
      open: vi.fn<(url: string) => typeof popup | null>(() => popup),
    })
    vi.stubGlobal("window", win)
    const deliver = (
      data: Record<string, unknown>,
      source: unknown = popup,
      from = origin
    ) =>
      win.dispatchEvent(
        Object.assign(new Event("message"), { origin: from, source, data })
      )
    const nonce = () =>
      new URL(win.open.mock.calls[0][0], origin).searchParams.get("popup_nonce")
    return { popup, win, deliver, nonce }
  }

  it("ignores foreign windows, origins and nonces, then trades the code", async () => {
    const { deliver, nonce } = setup()
    const fetch = stubFetch({
      "POST /api/v1/oidc/exchange": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({ code: "one-time" })
        return tokens("u1")
      },
    })
    const client = createAuthClient({ fetch })
    const pending = client.signInWithPopup("google")
    const ok = {
      type: "AUTHKIT_OIDC_RESULT",
      nonce: nonce(),
      code: "one-time",
      provider: "google",
    }
    deliver(ok, {})
    deliver(ok, undefined, "https://evil.example")
    deliver({ ...ok, nonce: "wrong" })
    expect(fetch).not.toHaveBeenCalled()
    deliver(ok)
    expect(await pending).toMatchObject({
      ok: true,
      result: { status: "complete" },
      provider: "google",
    })
    expect(client.getAccessToken()).toBe(jwt("u1"))
  })

  it("returns a pending step, or the error the popup reported", async () => {
    const { deliver, nonce, win } = setup()
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/oidc/exchange": [json(200, enrollment)],
      }),
    })
    const first = client.signInWithPopup("google")
    deliver({ type: "AUTHKIT_OIDC_RESULT", nonce: nonce(), code: "c" })
    expect(await first).toMatchObject({
      ok: true,
      result: { status: "enrollment_required" },
    })
    expect(client.getAccessToken()).toBeNull()

    const second = client.signInWithPopup("google")
    const secondNonce = new URL(
      win.open.mock.calls[1][0],
      origin
    ).searchParams.get("popup_nonce")
    deliver({
      type: "AUTHKIT_OIDC_ERROR",
      nonce: secondNonce,
      error: "access_denied",
      provider: "google",
    })
    expect(await second).toEqual({
      ok: false,
      reason: "provider_error",
      code: "access_denied",
      provider: "google",
    })
  })

  it("rejects a result after the session changed", async () => {
    const { deliver, nonce } = setup()
    const client = createAuthClient({
      fetch: vi.fn().mockResolvedValue(tokens("A")),
    })
    const pending = client.signInWithPopup("google")
    await signIn(client, "B")
    deliver({ type: "AUTHKIT_OIDC_RESULT", nonce: nonce(), code: "c" })
    expect(await pending).toEqual({ ok: false, reason: "session_changed" })
    expect(client.getSnapshot()).toMatchObject({ userId: "B" })
  })

  it("reports blocked, closed and timeout, cleaning up timers", async () => {
    const { popup, win } = setup()
    const client = createAuthClient()
    win.open.mockReturnValueOnce(null)
    expect(await client.signInWithPopup("google")).toEqual({
      ok: false,
      reason: "blocked",
    })

    const closing = client.signInWithPopup("google")
    popup.closed = true
    await vi.advanceTimersByTimeAsync(500)
    expect(await closing).toEqual({ ok: false, reason: "closed" })

    popup.closed = false
    const timing = client.signInWithPopup("google", { timeoutMs: 1000 })
    await vi.advanceTimersByTimeAsync(1000)
    expect(await timing).toEqual({ ok: false, reason: "timeout" })
    expect(vi.getTimerCount()).toBe(0)
  })
})
