// @vitest-environment jsdom
import { act, waitFor } from "@testing-library/react"
import { useEffect } from "react"
import { describe, expect, it, vi } from "vitest"

import { authError, authResult, json, stubFetch } from "../client/testing.ts"
import { memoryStorage } from "../client/testing-storage.ts"
import { useChangePassword, useSessions } from "./account.ts"
import {
  useAuthClient,
  usePermissions,
  useSession,
  useUser,
} from "./context.ts"
import {
  noContent,
  renderWithAuth,
  session,
  signedIn,
  token,
} from "./testing.tsx"
import { useLogin } from "./useLogin.ts"
import { useRegister } from "./useRegister.ts"
import { useAuth } from "./useAuth.ts"
import { useStepUp } from "./useStepUp.ts"

const me = (id: string) => json(200, { id, username: id, providers: [] })

const emailFactor = {
  id: "f-email",
  method: "email",
  is_default: true,
  destination: "a***@x.test",
}
const totpFactor = {
  id: "f-totp",
  method: "totp",
  is_default: false,
  destination: null,
}

const secondFactor = (
  factor: typeof emailFactor | typeof totpFactor = emailFactor,
  challenge = "ch-1"
) =>
  json(
    200,
    authResult("second_factor_required", {
      second_factor: {
        user_id: "u1",
        challenge,
        factor,
        factors: [emailFactor, totpFactor],
      },
    })
  )

describe("AuthProvider", () => {
  it("restores, shares /me per session and reports session boundaries", async () => {
    let meCalls = 0
    const fetch = stubFetch({
      "POST /api/v1/token": [
        authError(401, "invalid_token"),
        session({ sub: "u1", sid: "s1", auth_time: 1 }),
      ],
      "POST /api/v1/password/login": () =>
        session({ sub: "u1", sid: "s1", auth_time: 1 }),
      "GET /api/v1/me": () => (meCalls++, me("u1")),
      "DELETE /api/v1/logout": noContent,
    })
    const onSessionChange = vi.fn()
    const { result, client } = renderWithAuth(
      () => ({ session: useSession(), a: useUser(), b: useUser() }),
      fetch,
      { autoStart: true, onSessionChange }
    )
    await waitFor(() =>
      expect(result.current.session).toMatchObject({ status: "anonymous" })
    )
    expect(result.current.a).toMatchObject({ user: null, loading: false })

    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "b" })
    )
    await waitFor(() => expect(result.current.a.user?.id).toBe("u1"))
    expect(result.current.b.user?.id).toBe("u1")
    expect(meCalls).toBe(1)
    expect(onSessionChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "authenticated", userId: "u1" }),
      expect.objectContaining({ status: "anonymous" })
    )

    // A silent refresh of the same session neither refetches nor notifies.
    const notified = onSessionChange.mock.calls.length
    await act(() => client.refresh())
    expect(meCalls).toBe(1)
    expect(onSessionChange).toHaveBeenCalledTimes(notified)

    await act(() => client.signOut())
    expect(result.current.a).toMatchObject({ user: null, loading: false })
    expect(onSessionChange).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: "anonymous", reason: "signed_out" }),
      expect.objectContaining({ status: "authenticated" })
    )
  })

  it("reads the role and its expanded permissions", async () => {
    const fetch = stubFetch({
      "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
      "GET /api/v1/me/permissions": ({ url }) => {
        expect(url).toContain("group_id=g1")
        return json(200, {
          group_id: "g1",
          role: "channel:moderator",
          permissions: ["root:tags:read", "root:tags:update"],
        })
      },
    })
    const { result, client } = renderWithAuth(
      () => usePermissions({ groupId: "g1" }),
      fetch
    )
    expect(result.current).toMatchObject({ permissions: null, loading: false })
    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "b" })
    )
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.role).toBe("channel:moderator")
    expect(result.current.has("root:tags:update")).toBe(true)
    expect(result.current.has("root:users:update")).toBe(false)
  })
})

describe("useLogin", () => {
  it("password → 2FA challenge → switch factor → verify", async () => {
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "POST /api/v1/password/login": [secondFactor()],
      "POST /api/v1/2fa/challenge": ({ body }) => {
        expect(JSON.parse(String(body))).toMatchObject({ factor_id: "f-totp" })
        return secondFactor(totpFactor, "ch-2")
      },
      "POST /api/v1/2fa/verify": [
        authError(401, "invalid_2fa_code"),
        session({ sub: "u1", sid: "s1" }),
      ],
    })
    const { result } = renderWithAuth(() => useLogin({ onSignedIn }), fetch)

    await act(() => result.current.signIn({ identifier: "a", password: "pw" }))
    expect(result.current.state).toMatchObject({
      step: "two_factor",
      challenge: { challenge: "ch-1", factor: emailFactor },
    })

    await act(() => result.current.sendTwoFactorCode("f-totp"))
    expect(result.current.state).toMatchObject({
      step: "two_factor",
      challenge: { challenge: "ch-2", factor: totpFactor },
    })

    await act(() => result.current.verifyTwoFactor("000000"))
    expect(result.current.error?.code).toBe("invalid_2fa_code")
    expect(result.current.state.step).toBe("two_factor")

    await act(() => result.current.verifyTwoFactor(" 123456 "))
    expect(JSON.parse(String(fetch.mock.lastCall?.[1]?.body))).toEqual({
      user_id: "u1",
      challenge: "ch-2",
      code: "123456",
      factor_id: "f-totp",
    })
    expect(result.current.error).toBeNull()
    expect(result.current.state).toEqual({ step: "done" })
    expect(onSignedIn).toHaveBeenCalledOnce()
  })

  it("forced enrollment uses the enrollment token and shows backup codes", async () => {
    const onSignedIn = vi.fn()
    const auths: (string | null)[] = []
    const enrollmentToken = token({ sub: "u1", typ: "enroll" })
    const fetch = stubFetch({
      "POST /api/v1/password/login": [
        json(
          200,
          authResult("enrollment_required", {
            return_to: "/settings",
            enrollment: {
              token_set: {
                access_token: enrollmentToken,
                token_type: "Bearer",
                expires_in: 600,
                refresh_token: null,
              },
              allowed_methods: ["totp", "email"],
            },
          })
        ),
      ],
      "POST /api/v1/me/2fa/setup": ({ headers }) => {
        auths.push(new Headers(headers).get("Authorization"))
        return json(200, {
          method: "totp",
          destination: null,
          secret: "S3CR3T",
          otpauth_uri: "otp",
        })
      },
      "POST /api/v1/me/2fa/factors": ({ headers, body }) => {
        auths.push(new Headers(headers).get("Authorization"))
        expect(JSON.parse(String(body))).toEqual({
          method: "totp",
          code: "123456",
        })
        return json(201, {
          factor: totpFactor,
          backup_codes: ["b1", "b2"],
          auth: signedIn({ sub: "u1", sid: "s1" }),
        })
      },
    })
    const { result, client } = renderWithAuth(
      () => useLogin({ onSignedIn }),
      fetch
    )
    await act(() => result.current.signIn({ identifier: "a", password: "pw" }))
    expect(result.current.state.step).toBe("enrollment")

    await act(() => result.current.startEnrollment({ method: "totp" }))
    expect(result.current.state).toMatchObject({
      step: "enrollment",
      method: "totp",
      totp: { secret: "S3CR3T", otpauthUri: "otp" },
    })

    await act(() => result.current.confirmEnrollment("123456"))
    expect(auths).toEqual([
      `Bearer ${enrollmentToken}`,
      `Bearer ${enrollmentToken}`,
    ])
    expect(result.current.state).toEqual({
      step: "backup_codes",
      codes: ["b1", "b2"],
      returnTo: "/settings",
    })
    expect(client.getSnapshot().status).toBe("authenticated")
    expect(onSignedIn).not.toHaveBeenCalled()

    act(() => result.current.acknowledgeBackupCodes())
    expect(result.current.state).toEqual({
      step: "done",
      returnTo: "/settings",
    })
    expect(onSignedIn).toHaveBeenCalledWith({ returnTo: "/settings" })
  })

  it("restores a deleted account and signs straight back in", async () => {
    const recovery = {
      token: "rec-1",
      expires_at: "2030-01-01T00:00:00Z",
      purge_at: "2030-02-01T00:00:00Z",
    }
    const fetch = stubFetch({
      "POST /api/v1/password/login": [
        json(200, authResult("account_recovery_required", { recovery })),
        session({ sub: "u1", sid: "s1" }),
      ],
      "POST /api/v1/account/recovery/confirm": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({ token: "rec-1" })
        return noContent()
      },
    })
    const { result } = renderWithAuth(() => useLogin(), fetch)
    await act(() => result.current.signIn({ identifier: "a", password: "pw" }))
    expect(result.current.state).toEqual({ step: "recovery", recovery })
    await act(() => result.current.confirmRecovery())
    expect(result.current.state).toEqual({ step: "done" })
  })

  it("verification_required → confirm code signs in", async () => {
    const verification = {
      identifier: "a@x.test",
      channel: "email",
      password_proof: "pp",
    }
    const fetch = stubFetch({
      "POST /api/v1/password/login": [
        json(200, authResult("verification_required", { verification })),
      ],
      "POST /api/v1/verify/request": () => new Response(null, { status: 202 }),
      "POST /api/v1/verify/confirm": () => session({ sub: "u1", sid: "s1" }),
    })
    const { result } = renderWithAuth(() => useLogin(), fetch)
    await act(() => result.current.signIn({ identifier: "a", password: "pw" }))
    expect(result.current.state).toEqual({
      step: "verification",
      verification,
    })
    await act(() => result.current.resendVerification())
    await act(() => result.current.confirmVerification("abc123"))
    expect(result.current.state).toEqual({ step: "done" })
  })
})

describe("useRegister", () => {
  it("registers, verifies (which signs in) and can abandon", async () => {
    const onSignedIn = vi.fn()
    const bodies: unknown[] = []
    const fetch = stubFetch({
      "GET /api/v1/register/availability": () =>
        json(200, { username: { available: false, error: "taken" } }),
      "POST /api/v1/register": ({ body }) => {
        bodies.push(JSON.parse(String(body)))
        return new Response(null, { status: 202 })
      },
      "POST /api/v1/verify/request": () => new Response(null, { status: 202 }),
      "POST /api/v1/register/abandon": noContent,
      "POST /api/v1/verify/confirm": () => session({ sub: "u1", sid: "s1" }),
    })
    const { result } = renderWithAuth(
      () => useRegister({ onSignedIn, inviteCode: "inv-1" }),
      fetch
    )
    await act(async () => {
      await result.current.checkAvailability({ username: "neo" })
    })
    expect(result.current.availability?.username?.available).toBe(false)

    const input = { identifier: "n@x.test", username: "neo", password: "pw" }
    await act(() => result.current.register(input))
    expect(result.current.state).toEqual({
      step: "verify",
      identifier: "n@x.test",
      channel: "email",
    })
    await act(() => result.current.abandon())
    expect(result.current.state).toEqual({ step: "form" })

    await act(() => result.current.register(input))
    await act(() => result.current.resend())
    await act(() => result.current.verify("CODE"))
    expect(result.current.state).toEqual({ step: "done", signedIn: true })
    expect(onSignedIn).toHaveBeenCalledOnce()
    expect(bodies[0]).toMatchObject({ invite_code: "inv-1" })
  })
})

describe("useStepUp", () => {
  const stepUpRequired = () =>
    authError(401, "step_up_required", {
      step_up_methods: ["password", "github"],
      max_age_seconds: 900,
      factors: [],
    })

  it("guards a sensitive action: step up, then retry", async () => {
    const fetch = stubFetch({
      "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
      "PUT /api/v1/me/password": [stepUpRequired(), noContent()],
      "POST /api/v1/me/step-up/password": [
        authError(401, "invalid_password"),
        json(
          200,
          signedIn(
            { sub: "u1", sid: "s1", auth_time: 2 },
            {
              fresh_auth: {
                last_authenticated_at: null,
                step_up_required_for_sensitive_actions: false,
                step_up_required_in_seconds: 900,
                auth_methods: ["pwd"],
              },
            }
          )
        ),
      ],
    })
    const { result, client } = renderWithAuth(() => {
      const stepUp = useStepUp()
      return { stepUp, change: useChangePassword({ guard: stepUp.guard }) }
    }, fetch)
    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "pw" })
    )

    let pending!: Promise<unknown>
    act(() => {
      pending = result.current.change.changePassword({ newPassword: "new-pw" })
    })
    await waitFor(() =>
      expect(result.current.stepUp.state).toMatchObject({
        step: "required",
        challenge: { methods: ["password", "github"], factors: [] },
      })
    )
    expect(result.current.change.busy).toBe(true)

    await act(() => result.current.stepUp.withPassword("wrong"))
    expect(result.current.stepUp.error?.code).toBe("invalid_password")
    expect(result.current.stepUp.state.step).toBe("required")

    await act(() => result.current.stepUp.withPassword("pw"))
    await act(() => pending)
    expect(result.current.stepUp.state).toEqual({ step: "idle" })
    expect(result.current.change).toMatchObject({ state: "done", error: null })
    expect(client.getSnapshot()).toMatchObject({ claims: { auth_time: 2 } })
  })

  it("2FA step-up sends a code first; cancel rejects quietly", async () => {
    const fetch = stubFetch({
      "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
      "PUT /api/v1/me/password": [
        authError(401, "step_up_required", {
          step_up_methods: ["2fa"],
          max_age_seconds: 900,
          factors: [
            { id: "f1", method: "totp", is_default: true, destination: null },
            {
              id: "f2",
              method: "email",
              is_default: false,
              destination: "a***@x.test",
            },
          ],
        }),
      ],
      "POST /api/v1/me/step-up/2fa/send": ({ body }) => {
        expect(JSON.parse(String(body))).toEqual({ factor_id: "f2" })
        return new Response(null, { status: 202 })
      },
    })
    const { result, client } = renderWithAuth(() => {
      const stepUp = useStepUp()
      return { stepUp, change: useChangePassword({ guard: stepUp.guard }) }
    }, fetch)
    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "pw" })
    )
    let pending!: Promise<unknown>
    act(() => {
      pending = result.current.change.changePassword({ newPassword: "x" })
    })
    await waitFor(() =>
      expect(result.current.stepUp.state).toMatchObject({
        step: "required",
        challenge: { methods: ["2fa"] },
      })
    )
    await act(() => result.current.stepUp.sendCode("f2"))
    expect(result.current.stepUp.state).toMatchObject({
      step: "code_sent",
      factorId: "f2",
      destination: "a***@x.test",
    })
    act(() => result.current.stepUp.cancel())
    await act(() => pending)
    expect(result.current.stepUp.state).toEqual({ step: "idle" })
    expect(result.current.change).toMatchObject({
      state: "idle",
      busy: false,
      error: null,
    })
  })
})

describe("useSessions", () => {
  it("marks the current session, revokes one, then every other", async () => {
    const revoked: string[] = []
    const row = (id: string) => ({
      id,
      created_at: "",
      last_used_at: "",
      expires_at: null,
      ip: null,
      user_agent: null,
      current: id === "s1",
    })
    const fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (path === "/api/v1/password/login")
          return session({ sub: "u1", sid: "s1" })
        if (path === "/api/v1/me/sessions" && init?.method === "GET")
          return json(200, {
            data: ["s1", "s2", "s3"].map(row),
            next_cursor: null,
            total: null,
          })
        if (init?.method === "DELETE") {
          revoked.push(path.replace("/api/v1/me/sessions", "") || "others")
          return noContent()
        }
        throw new Error(`unexpected ${path}`)
      }
    )
    const { result, client } = renderWithAuth(
      () => ({ sessions: useSessions(), client: useAuthClient() }),
      fetch
    )
    expect(result.current.sessions.sessions).toBeNull()
    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "pw" })
    )
    await waitFor(() => expect(result.current.sessions.loading).toBe(false))
    expect(
      result.current.sessions.sessions?.map((s) => [s.id, s.current])
    ).toEqual([
      ["s1", true],
      ["s2", false],
      ["s3", false],
    ])
    await act(() => result.current.sessions.revoke(["s2"]))
    expect(revoked).toEqual(["/s2"])
    expect(result.current.sessions.sessions?.map((s) => s.id)).toEqual([
      "s1",
      "s3",
    ])
    await act(() => result.current.sessions.revokeOthers())
    expect(revoked).toEqual(["/s2", "others"])
    expect(result.current.sessions.sessions?.map((s) => s.id)).toEqual(["s1"])
    expect(client.getSnapshot().status).toBe("authenticated")
  })
})

describe("useAuth", () => {
  it("renders the hinted user while restoring and reports user changes only", async () => {
    const storage = memoryStorage()
    storage.setItem(
      "authkit:session:/api/v1",
      JSON.stringify({
        userId: "u1",
        username: "ann",
        expiresAt: Date.now() + 60_000,
      })
    )
    const fetch = stubFetch({
      "POST /api/v1/token": [session({ sub: "u1", sid: "s1" })],
      "GET /api/v1/me": () => me("u1"),
      "DELETE /api/v1/logout": noContent,
    })
    const onUserChange = vi.fn()
    const onSessionChange = vi.fn()
    const { result, client } = renderWithAuth(
      () => useAuth(),
      fetch,
      { autoStart: true, onUserChange, onSessionChange },
      { sessionHint: { storage } }
    )
    expect(result.current).toMatchObject({
      status: "restoring",
      signedIn: true,
      userId: "u1",
      hint: { username: "ann" },
    })
    await waitFor(() =>
      expect(result.current).toMatchObject({
        status: "signed_in",
        user: { id: "u1" },
      })
    )
    expect(onUserChange).not.toHaveBeenCalled()

    // A same-user session rotation, e.g. after proving an address.
    await act(() =>
      client.completeSignIn(async () => signedIn({ sub: "u1", sid: "s2" }))
    )
    expect(onSessionChange).toHaveBeenCalled()
    expect(onUserChange).not.toHaveBeenCalled()
    expect(result.current.user).toMatchObject({ id: "u1" })

    await act(() => client.signOut())
    expect(onUserChange).toHaveBeenLastCalledWith(null, "u1")
    expect(result.current).toMatchObject({
      status: "signed_out",
      signedIn: false,
      user: null,
    })
    expect(storage.getItem("authkit:session:/api/v1")).toBeNull()
  })
})

describe("AuthProvider restore order", () => {
  it("starts before children's effects, so their first requests carry the session", async () => {
    const fetch = stubFetch({
      "POST /api/v1/token": [session({ sub: "u1" })],
      "GET /host/thing": ({ headers }) =>
        json(200, { auth: new Headers(headers).get("Authorization") }),
    })
    let seen: unknown = null
    renderWithAuth(
      () => {
        const client = useAuthClient()
        useEffect(() => {
          void client
            .authFetch("/host/thing")
            .then((res) => res.json())
            .then((body) => (seen = body))
        }, [client])
      },
      fetch,
      { autoStart: true }
    )
    await waitFor(() =>
      expect(seen).toEqual({ auth: `Bearer ${token({ sub: "u1" })}` })
    )
  })

  it("remembers the username in the session hint once /me loads", async () => {
    const storage = memoryStorage()
    const fetch = stubFetch({
      "POST /api/v1/token": [session({ sub: "u1" })],
      "GET /api/v1/me": () => me("u1"),
    })
    const { result } = renderWithAuth(
      () => useAuth(),
      fetch,
      { autoStart: true },
      { sessionHint: { storage } }
    )
    await waitFor(() => expect(result.current.user).toMatchObject({ id: "u1" }))
    await waitFor(() =>
      expect(
        JSON.parse(storage.getItem("authkit:session:/api/v1") ?? "{}")
      ).toMatchObject({ userId: "u1", username: "u1" })
    )
  })
})

describe("signed-out restore", () => {
  it("settles signed out quietly and lets public requests through", async () => {
    const fetch = stubFetch({
      "POST /api/v1/token": [authError(401, "no_session")],
      "GET /public/feed": ({ headers }) =>
        json(200, { auth: new Headers(headers).get("Authorization") }),
    })
    let feed: unknown = null
    const { result } = renderWithAuth(
      () => {
        const client = useAuthClient()
        useEffect(() => {
          void client
            .authFetch("/public/feed")
            .then((res) => res.json())
            .then((body) => (feed = body))
        }, [client])
        return useAuth()
      },
      fetch,
      { autoStart: true }
    )
    await waitFor(() =>
      expect(result.current).toMatchObject({
        status: "signed_out",
        signedIn: false,
        user: null,
      })
    )
    await waitFor(() => expect(feed).toEqual({ auth: null }))
    expect(result.current.session).toMatchObject({ continuation: null })
    expect(
      fetch.mock.calls.filter(([input]) => String(input).endsWith("/token"))
    ).toHaveLength(1)
  })
})
