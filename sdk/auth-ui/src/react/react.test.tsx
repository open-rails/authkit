// @vitest-environment jsdom
import { act, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"

import { authError, json, stubFetch } from "../client/testing.ts"
import { useChangePassword, useSessions } from "./account.ts"
import {
  useAuthClient,
  usePermissions,
  useSession,
  useUser,
} from "./context.ts"
import { noContent, renderWithAuth, session, token } from "./testing.tsx"
import { useLogin } from "./useLogin.ts"
import { useRegister } from "./useRegister.ts"
import { useStepUp } from "./useStepUp.ts"

const me = (id: string) => json(200, { id, username: id, security: {} })

const twoFactorRequired = (extra: Record<string, unknown> = {}) =>
  authError(403, "2fa_required", {
    user_id: "u1",
    challenge: "ch-1",
    method: "email",
    verification_id: "a***@x.test",
    default_factor: { id: "f-email", method: "email", is_default: true },
    available_factors: [
      { id: "f-email", method: "email" },
      { id: "f-totp", method: "totp" },
    ],
    ...extra,
  })

describe("AuthProvider", () => {
  it("restores, shares /me per session and reports session boundaries", async () => {
    let meCalls = 0
    const fetch = stubFetch({
      "POST /api/v1/token": [
        authError(401, "invalid_refresh_token"),
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

  it("checks permissions with AuthKit glob semantics", async () => {
    const fetch = stubFetch({
      "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
      "GET /api/v1/me/permissions": ({ url }) => {
        expect(url).toContain("persona=staff")
        return json(200, {
          object: "permission_set",
          permissions: ["root:tags:*"],
        })
      },
    })
    const { result, client } = renderWithAuth(
      () => usePermissions({ persona: "staff" }),
      fetch
    )
    expect(result.current).toMatchObject({ permissions: null, loading: false })
    await act(() =>
      client.signInWithPassword({ identifier: "a", password: "b" })
    )
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.has("root:tags:update")).toBe(true)
    expect(result.current.has("root:users:update")).toBe(false)
  })
})

describe("useLogin", () => {
  it("password → 2FA challenge → switch factor → verify", async () => {
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "POST /api/v1/password/login": [twoFactorRequired()],
      "POST /api/v1/2fa/challenge": ({ body }) => {
        expect(JSON.parse(String(body))).toMatchObject({ factor_id: "f-totp" })
        return twoFactorRequired({ method: "totp", challenge: "ch-2" })
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
      factorId: "f-email",
      challenge: { method: "email", verificationId: "a***@x.test" },
    })

    await act(() => result.current.sendTwoFactorCode("f-totp"))
    expect(result.current.state).toMatchObject({
      step: "two_factor",
      factorId: "f-totp",
      challenge: { challenge: "ch-2", method: "totp" },
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
    const fetch = stubFetch({
      "POST /api/v1/password/login": [
        authError(403, "2fa_enrollment_required", {
          user_id: "u1",
          allowed_methods: ["totp", "email"],
          enrollment_token: "enroll-tok",
          enrollment_expires_in: 600,
          return_to: "/settings",
        }),
      ],
      "POST /api/v1/user/2fa": ({ headers, body }) => {
        auths.push(new Headers(headers).get("Authorization"))
        return JSON.parse(String(body)).code
          ? json(200, {
              enabled: true,
              method: "totp",
              backup_codes: ["b1", "b2"],
              access_token: token({ sub: "u1", sid: "s1" }),
            })
          : json(200, { method: "totp", secret: "S3CR3T", otpauth_uri: "otp" })
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
    expect(auths).toEqual(["Bearer enroll-tok", "Bearer enroll-tok"])
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
        authError(409, "account_recovery_required", { recovery }),
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
    const fetch = stubFetch({
      "POST /api/v1/password/login": [
        authError(403, "verification_required", {
          identifier: "a@x.test",
          channel: "email",
        }),
      ],
      "POST /api/v1/verify/request": () => new Response(null, { status: 202 }),
      "POST /api/v1/verify/confirm": () => session({ sub: "u1", sid: "s1" }),
    })
    const { result } = renderWithAuth(() => useLogin(), fetch)
    await act(() => result.current.signIn({ identifier: "a", password: "pw" }))
    expect(result.current.state).toEqual({
      step: "verification",
      identifier: "a@x.test",
      channel: "email",
    })
    await act(() => result.current.resendVerification())
    await act(() => result.current.confirmVerification("abc123"))
    expect(result.current.state).toEqual({ step: "done" })
  })
})

describe("useRegister", () => {
  it("registers, verifies (which signs in) and can abandon", async () => {
    const onSignedIn = vi.fn()
    const fetch = stubFetch({
      "GET /api/v1/register/availability": () =>
        json(200, { username: { available: false, error: "taken" } }),
      "POST /api/v1/register": () =>
        json(202, {
          next_action: "verify_email",
          user: { username: "neo", email: "n@x.test", phone_number: null },
        }),
      "POST /api/v1/register/resend": () => new Response(null, { status: 202 }),
      "POST /api/v1/register/abandon": noContent,
      "POST /api/v1/verify/confirm": () => session({ sub: "u1", sid: "s1" }),
    })
    const { result } = renderWithAuth(() => useRegister({ onSignedIn }), fetch)
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
  })
})

describe("useStepUp", () => {
  const stepUpRequired = () =>
    authError(403, "step_up_required", {
      step_up_methods: ["password", "2fa"],
      max_age_seconds: 900,
    })

  it("guards a sensitive action: step up, then retry", async () => {
    const fetch = stubFetch({
      "POST /api/v1/password/login": () => session({ sub: "u1", sid: "s1" }),
      "POST /api/v1/user/password": [stepUpRequired(), json(200, {})],
      "POST /api/v1/step-up/password": [
        authError(401, "invalid_password"),
        json(200, {
          token_set: {
            access_token: token({ sub: "u1", sid: "s1", auth_time: 2 }),
          },
          fresh_auth: { step_up_required_for_sensitive_actions: false },
        }),
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
        challenge: { methods: ["password", "2fa"], mfaRequired: false },
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
      "POST /api/v1/user/password": [
        authError(403, "step_up_required", {
          step_up_methods: ["password", "2fa"],
          mfa_required: true,
        }),
      ],
      "POST /api/v1/step-up/2fa": [
        authError(403, "2fa_required", {
          method: "email",
          verification_id: "a***@x.test",
        }),
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
      pending = result.current.change.changePassword({ newPassword: "x" })
    })
    await waitFor(() =>
      expect(result.current.stepUp.state).toMatchObject({
        step: "required",
        challenge: { methods: ["2fa"], mfaRequired: true },
      })
    )
    await act(() => result.current.stepUp.sendCode("email"))
    expect(result.current.stepUp.state).toMatchObject({
      step: "code_sent",
      method: "email",
      verificationId: "a***@x.test",
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
  it("marks the current session and revokes in a batch", async () => {
    const revoked: string[] = []
    const row = (id: string) => ({
      session_id: id,
      family_id: "f",
      created_at: "",
      last_used_at: "",
      expires_at: "",
    })
    const fetch = vi.fn(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (path === "/api/v1/password/login")
          return session({ sub: "u1", sid: "s1" })
        if (path === "/api/v1/user/sessions")
          return json(200, {
            object: "list",
            data: ["s1", "s2", "s3"].map(row),
          })
        if (init?.method === "DELETE") {
          revoked.push(path.split("/").pop()!)
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
      result.current.sessions.sessions?.map((s) => [s.session_id, s.current])
    ).toEqual([
      ["s1", true],
      ["s2", false],
      ["s3", false],
    ])
    await act(() => result.current.sessions.revoke(["s2", "s3"]))
    expect(revoked.sort()).toEqual(["s2", "s3"])
    expect(result.current.sessions.sessions?.map((s) => s.session_id)).toEqual([
      "s1",
    ])
  })
})
