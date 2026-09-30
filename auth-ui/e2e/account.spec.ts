import { expect, test } from "@playwright/test"

import { accessToken, api, outbox, registerVerified, totp } from "./support/api"

type ErrorBody = { error: { code: string; metadata: Record<string, unknown> } }

test("TOTP 2FA, step-up, delete and recover", async ({ page, request }) => {
  await page.goto("/")
  const { email, password, access } = await registerVerified(page, request)

  // TOTP steps must increase (now, then +1 step); start early in a step.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()

  const setup = await api(
    page,
    "POST",
    "/me/2fa/setup",
    { method: "totp" },
    access
  )
  expect(setup.status, JSON.stringify(setup.body)).toBe(200)
  const secret = setup.body!.secret as string
  const created = await api(
    page,
    "POST",
    "/me/2fa/factors",
    { method: "totp", code: totp(secret, now) },
    access
  )
  expect(created.status, JSON.stringify(created.body)).toBe(201)
  expect(created.body).toMatchObject({
    factor: { method: "totp", is_default: true, destination: null },
  })
  const backupCodes = created.body!.backup_codes as string[]
  expect(backupCodes.length).toBeGreaterThan(0)

  // Sign-in answers 200 with the next step, never an error envelope.
  const challenge = async () => {
    const res = await api(page, "POST", "/password/login", {
      identifier: email,
      password,
    })
    expect(res.status, JSON.stringify(res.body)).toBe(200)
    expect(res.body).toMatchObject({
      status: "second_factor_required",
      token_set: null,
      second_factor: { factor: { method: "totp" } },
    })
    const step = res.body!.second_factor as Record<string, unknown>
    return { user_id: step.user_id, challenge: step.challenge }
  }

  const session = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: totp(secret, now + 30_000),
  })
  expect(session.status, JSON.stringify(session.body)).toBe(200)
  const access2 = accessToken(session)

  // A password never re-proves an account with a second factor.
  const stepUp = await api(
    page,
    "POST",
    "/me/step-up/password",
    { password },
    access2
  )
  expect(stepUp.status).toBe(403)
  const stepUpError = (stepUp.body as ErrorBody).error
  expect(stepUpError.code).toBe("step_up_required")
  expect(stepUpError.metadata).toMatchObject({
    step_up_methods: ["2fa"],
    factors: [{ method: "totp", is_default: true, destination: null }],
  })

  // A fresh 2FA sign-in may delete the account.
  expect((await api(page, "DELETE", "/me", undefined, access2)).status).toBe(
    204
  )

  const recovery = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: backupCodes[0],
    backup_code: true,
  })
  expect(recovery.status, JSON.stringify(recovery.body)).toBe(200)
  expect(recovery.body).toMatchObject({
    status: "account_recovery_required",
    token_set: null,
  })
  const token = (recovery.body!.recovery as { token: string }).token
  expect(
    (await api(page, "POST", "/account/recovery/confirm", { token })).status
  ).toBe(204)

  const restored = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: backupCodes[1],
    backup_code: true,
  })
  expect(restored.status, JSON.stringify(restored.body)).toBe(200)
  accessToken(restored)
})

test("profile, contact change and sessions under /me", async ({
  page,
  request,
}) => {
  await page.goto("/")
  const { email, password, access } = await registerVerified(page, request)

  const renamed = await api(
    page,
    "PATCH",
    "/me",
    { preferred_language: "de" },
    access
  )
  expect(renamed.status, JSON.stringify(renamed.body)).toBe(200)
  expect(renamed.body).toMatchObject({
    email,
    preferred_language: "de",
    has_password: true,
    providers: [],
  })

  // A second sign-in (its refresh cookie replaces the first's), then sign
  // every other session out.
  const other = await api(page, "POST", "/password/login", {
    identifier: email,
    password,
  })
  accessToken(other)
  const listed = await api(page, "GET", "/me/sessions", undefined, access)
  expect(listed.status).toBe(200)
  const sessions = listed.body!.data as { current: boolean }[]
  expect(sessions.length).toBeGreaterThanOrEqual(2)
  expect(sessions.filter((s) => s.current)).toHaveLength(1)
  expect(
    (await api(page, "DELETE", "/me/sessions", undefined, access)).status
  ).toBe(204)
  const after = await api(page, "GET", "/me/sessions", undefined, access)
  expect(after.body!.data).toHaveLength(1)
  const refreshOther = await api(page, "POST", "/token", {
    grant_type: "refresh_token",
  })
  expect(refreshOther.status, JSON.stringify(refreshOther.body)).toBe(401)

  // Contact change: a code goes to the new address, confirmed signed in.
  const newEmail = email.replace("e2e-", "moved-")
  const change = await api(
    page,
    "PUT",
    "/me/email",
    { email: newEmail },
    access
  )
  expect(change.status, JSON.stringify(change.body)).toBe(202)
  const code = (await outbox(request, newEmail)).findLast((m) => m.code)?.code
  const confirmed = await api(
    page,
    "POST",
    "/verify/confirm",
    { identifier: newEmail, code },
    access
  )
  // A signed-in proof keeps the session: 204, or its refreshed AuthResult.
  expect([200, 204], JSON.stringify(confirmed.body)).toContain(confirmed.status)
  const me = await api(page, "GET", "/me", undefined, access)
  expect(me.body).toMatchObject({ email: newEmail, email_verified: true })
})
