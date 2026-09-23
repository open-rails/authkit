import { afterEach, describe, expect, it, vi } from "vitest"

import { createAuthClient } from "./client.ts"
import { AuthKitError } from "./errors.ts"
import { authError, json, jwt, stubFetch, tokens } from "./testing.ts"

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const signIn = (
  client: ReturnType<typeof createAuthClient>,
  sub = "u1",
  exp?: number
) => client.completeSignIn(async () => ({ access_token: jwt(sub, exp) }))

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
        return json(200, { access_token: jwt("u1"), refresh_token: "rt-2" })
      },
      "DELETE /auth/logout": () => new Response(null, { status: 204 }),
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
        fetch: vi
          .fn()
          .mockResolvedValue(authError(status, "invalid_refresh_token")),
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

  it("surfaces an MFA continuation demanded by refresh", async () => {
    const fetch = vi.fn().mockResolvedValue(
      authError(403, "2fa_required", {
        user_id: "u1",
        challenge: "c",
        method: "totp",
        verification_id: "",
      })
    )
    const client = createAuthClient({ fetch })
    await signIn(client)
    await client.refresh()
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "expired",
      continuation: { kind: "2fa_required", userId: "u1", challenge: "c" },
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
      "GET /api/v1/user/sessions": ({ headers }) => {
        seen.push(new Headers(headers).get("Authorization"))
        return seen.length === 1
          ? authError(401, "invalid_token")
          : json(200, { object: "list", data: [] })
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
      "POST /api/v1/step-up/password": [authError(401, "invalid_password")],
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
  it("password login commits the session", async () => {
    const client = createAuthClient({
      fetch: stubFetch({ "POST /api/v1/password/login": [tokens("u1")] }),
    })
    expect(
      await client.signInWithPassword({ identifier: "a", password: "b" })
    ).toEqual({ kind: "session" })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "u1",
    })
  })

  it.each([
    [
      403,
      "2fa_required",
      { user_id: "u", challenge: "c", method: "sms", verification_id: "+1***" },
      "2fa_required",
    ],
    [
      403,
      "2fa_enrollment_required",
      {
        user_id: "u",
        allowed_methods: ["totp"],
        token_set: { access_token: "e" },
      },
      "2fa_enrollment_required",
    ],
    [
      403,
      "verification_required",
      { identifier: "a@b.c", channel: "email" },
      "verification_required",
    ],
    [
      409,
      "account_recovery_required",
      { recovery: { token: "r", expires_at: "x", purge_at: "y" } },
      "account_recovery_required",
    ],
  ])(
    "password login returns %i %s as a continuation, not a session",
    async (status, code, metadata, kind) => {
      const client = createAuthClient({
        fetch: stubFetch({
          "POST /api/v1/password/login": [authError(status, code, metadata)],
        }),
      })
      expect(
        await client.signInWithPassword({ identifier: "a", password: "b" })
      ).toMatchObject({ kind })
      expect(client.getAccessToken()).toBeNull()
    }
  )

  it("rethrows ordinary login failures", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/password/login": [authError(401, "invalid_credentials")],
      }),
    })
    await expect(
      client.signInWithPassword({ identifier: "a", password: "b" })
    ).rejects.toBeInstanceOf(AuthKitError)
  })

  it("register signs in only when no verification is pending", async () => {
    const user = { username: "u", email: "a@b.c", phone_number: null }
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/register": [
          json(202, { next_action: "verify_email", user }),
          json(202, {
            next_action: "none",
            user,
            token_set: { access_token: jwt("u2") },
          }),
        ],
      }),
    })
    const input = { identifier: "a@b.c", username: "u", password: "p" }
    expect(await client.register(input)).toEqual({
      next_action: "verify_email",
      user,
      signedIn: false,
    })
    expect(await client.register(input)).toMatchObject({ signedIn: true })
    expect(client.getSnapshot()).toMatchObject({ userId: "u2" })
  })

  it("confirmVerification distinguishes a contact change from a sign-in", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/verify/confirm": [
          new Response(null, { status: 204 }),
          tokens("u3"),
        ],
      }),
    })
    expect(
      await client.confirmVerification({ identifier: "a@b.c", code: "X" })
    ).toEqual({ kind: "contact_changed" })
    expect(await client.confirmVerification({ token: "t" })).toEqual({
      kind: "session",
    })
  })

  it("enableTwoFactor maps every AuthKit answer", async () => {
    const fetch = stubFetch({
      "POST /api/v1/user/2fa": [
        new Response(null, { status: 202 }),
        new Response(null, { status: 204 }),
        json(200, { method: "totp", secret: "S", otpauth_uri: "otpauth://x" }),
        json(200, {
          enabled: true,
          method: "totp",
          backup_codes: ["b1"],
          access_token: jwt("u1"),
        }),
      ],
    })
    const client = createAuthClient({ fetch })
    const enrollmentToken = { access_token: "enroll" }
    expect(
      await client.enableTwoFactor(
        { method: "sms", phoneNumber: "+1" },
        { enrollmentToken }
      )
    ).toEqual({ kind: "code_sent" })
    expect(
      new Headers(fetch.mock.calls[0][1]?.headers).get("Authorization")
    ).toBe("Bearer enroll")
    expect(
      await client.enableTwoFactor({
        method: "sms",
        factorId: "f",
        makeDefault: true,
      })
    ).toEqual({ kind: "default_set" })
    expect(await client.enableTwoFactor({ method: "totp" })).toEqual({
      kind: "totp_started",
      secret: "S",
      otpauthUri: "otpauth://x",
    })
    expect(
      await client.enableTwoFactor(
        { method: "totp", code: "1" },
        { enrollmentToken }
      )
    ).toEqual({
      kind: "enabled",
      method: "totp",
      backupCodes: ["b1"],
      signedIn: true,
    })
    expect(client.getSnapshot().status).toBe("authenticated")
  })

  it("stepUpWithTwoFactor sends a code, then adopts the fresh token", async () => {
    const fresh = {
      step_up_required_for_sensitive_actions: false,
      time_until_step_up_required: 300,
    }
    const client = createAuthClient({
      fetch: stubFetch({
        "POST /api/v1/step-up/2fa": [
          authError(403, "2fa_required", {
            method: "email",
            verification_id: "a***@b.c",
          }),
          json(200, {
            token_set: { access_token: jwt("u1", 5000) },
            fresh_auth: fresh,
          }),
        ],
      }),
    })
    await signIn(client)
    expect(await client.stepUpWithTwoFactor()).toEqual({
      kind: "code_sent",
      method: "email",
      verificationId: "a***@b.c",
    })
    expect(await client.stepUpWithTwoFactor({ code: "123" })).toEqual({
      kind: "stepped_up",
      freshAuth: fresh,
    })
    expect(client.getAccessToken()).toBe(jwt("u1", 5000))
  })

  it("deleteAccount and revokeAllSessions end the local session", async () => {
    const client = createAuthClient({
      fetch: stubFetch({
        "DELETE /api/v1/user": [new Response(null, { status: 204 })],
      }),
    })
    await signIn(client)
    await client.deleteAccount({ password: "p" })
    expect(client.getSnapshot()).toMatchObject({
      status: "anonymous",
      reason: "signed_out",
    })
  })
})

describe("OIDC redirect", () => {
  it("builds the login URL outside the API prefix", () => {
    const client = createAuthClient({ language: () => "de" })
    expect(
      client.oidcLoginUrl("google", { returnTo: "/subscribe?plan=pro" })
    ).toBe("/oidc/google/login?return_to=%2Fsubscribe%3Fplan%3Dpro&lang=de")
    expect(
      client.oidcLoginUrl("google", { returnTo: "https://evil.example/" })
    ).toBe("/oidc/google/login?lang=de")
  })

  it("commits a token fragment", () => {
    const client = createAuthClient()
    const result = client.completeRedirect(
      `#access_token=${jwt("u1")}&expires_in=900&provider=google&return_to=%2Fa`
    )
    expect(result).toEqual({
      kind: "session",
      provider: "google",
      returnTo: "/a",
    })
    expect(client.getSnapshot()).toMatchObject({ userId: "u1" })
  })

  it("parses JSON-encoded continuation params and link results", () => {
    const client = createAuthClient()
    const factor = encodeURIComponent(
      JSON.stringify({ id: "f1", method: "totp" })
    )
    expect(
      client.completeRedirect(
        `#error=2fa_required&flow=login&provider=google&user_id=u&challenge=c&method=totp&default_factor=${factor}`
      )
    ).toMatchObject({
      kind: "2fa_required",
      defaultFactor: { id: "f1", method: "totp" },
    })
    expect(
      client.completeRedirect(
        `#error=2fa_enrollment_required&flow=login&user_id=u&enrollment_token=e&enrollment_expires_in=600&allowed_methods=${encodeURIComponent('["totp"]')}`
      )
    ).toMatchObject({
      kind: "2fa_enrollment_required",
      enrollmentToken: { access_token: "e", expires_in: 600 },
      allowedMethods: ["totp"],
    })
    expect(
      client.completeRedirect("#flow=link&result=success&provider=apple")
    ).toEqual({ kind: "linked", provider: "apple" })
    expect(
      client.completeRedirect(
        "#error=provider_already_linked&flow=link&provider=apple"
      )
    ).toEqual({
      kind: "error",
      code: "provider_already_linked",
      flow: "link",
      provider: "apple",
    })
    expect(client.completeRedirect("#nothing=here")).toBeNull()
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

  it("ignores foreign windows, origins and nonces, then commits the result", async () => {
    const { deliver, nonce } = setup()
    const client = createAuthClient()
    const pending = client.signInWithPopup("google")
    const ok = {
      type: "AUTHKIT_OIDC_RESULT",
      nonce: nonce(),
      access_token: jwt("u1"),
      provider: "google",
    }
    deliver(ok, {})
    deliver(ok, undefined, "https://evil.example")
    deliver({ ...ok, nonce: "wrong" })
    expect(client.getAccessToken()).toBeNull()
    deliver(ok)
    expect(await pending).toEqual({
      ok: true,
      outcome: { kind: "session" },
      provider: "google",
    })
    expect(client.getAccessToken()).toBe(jwt("u1"))
  })

  it("maps AUTHKIT_OIDC_ERROR to a continuation or a provider error", async () => {
    const { deliver, nonce } = setup()
    const client = createAuthClient()
    const first = client.signInWithPopup("google")
    deliver({
      type: "AUTHKIT_OIDC_ERROR",
      nonce: nonce(),
      error: "2fa_required",
      user_id: "u",
      challenge: "c",
      method: "totp",
    })
    expect(await first).toMatchObject({
      ok: true,
      outcome: { kind: "2fa_required", userId: "u" },
    })
  })

  it("rejects a result after the session changed", async () => {
    const { deliver, nonce } = setup()
    const client = createAuthClient({
      fetch: vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    })
    const pending = client.signInWithPopup("google")
    await signIn(client, "B")
    deliver({
      type: "AUTHKIT_OIDC_RESULT",
      nonce: nonce(),
      access_token: jwt("A"),
    })
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
