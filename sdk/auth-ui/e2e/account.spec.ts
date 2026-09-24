import { expect, test } from "@playwright/test"

import { api, registerVerified, totp } from "./support/api"

type ErrorBody = { error: { code: string; metadata: Record<string, unknown> } }

test("TOTP 2FA, step-up, delete and recover", async ({ page, request }) => {
  await page.goto("/")
  const { email, password, access } = await registerVerified(page, request)

  // TOTP steps must increase (now, then +1 step); start early in a step.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()

  const start = await api(page, "POST", "/user/2fa", { method: "totp" }, access)
  expect(start.status).toBe(200)
  const secret = start.body!.secret as string
  const enabled = await api(
    page,
    "POST",
    "/user/2fa",
    { method: "totp", code: totp(secret, now) },
    access
  )
  expect(enabled.status, JSON.stringify(enabled.body)).toBe(200)
  expect(enabled.body).toMatchObject({ enabled: true, method: "totp" })
  const backupCodes = enabled.body!.backup_codes as string[]
  expect(backupCodes.length).toBeGreaterThan(0)

  const challenge = async () => {
    const res = await api(page, "POST", "/password/login", {
      identifier: email,
      password,
    })
    expect(res.status).toBe(403)
    const { error } = res.body as ErrorBody
    expect(error.code).toBe("2fa_required")
    expect(error.metadata).toMatchObject({ method: "totp" })
    return {
      user_id: error.metadata.user_id,
      challenge: error.metadata.challenge,
    }
  }

  const session = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: totp(secret, now + 30_000),
  })
  expect(session.status, JSON.stringify(session.body)).toBe(200)
  const access2 = session.body!.access_token as string

  const stepUp = await api(
    page,
    "POST",
    "/step-up/password",
    { password },
    access2
  )
  expect(stepUp.status).toBe(200)
  expect(stepUp.body).toHaveProperty("token_set.access_token")
  expect(stepUp.body).toHaveProperty("fresh_auth.auth_methods")

  expect((await api(page, "DELETE", "/user", undefined, access2)).status).toBe(
    204
  )

  const recovery = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: backupCodes[0],
    backup_code: true,
  })
  expect(recovery.status, JSON.stringify(recovery.body)).toBe(409)
  const { error } = recovery.body as ErrorBody
  expect(error.code).toBe("account_recovery_required")
  const token = (error.metadata.recovery as { token: string }).token
  expect(
    (await api(page, "POST", "/account/recovery/confirm", { token })).status
  ).toBe(204)

  const restored = await api(page, "POST", "/2fa/verify", {
    ...(await challenge()),
    code: backupCodes[1],
    backup_code: true,
  })
  expect(restored.status, JSON.stringify(restored.body)).toBe(200)
  expect(restored.body).toHaveProperty("access_token")
})
