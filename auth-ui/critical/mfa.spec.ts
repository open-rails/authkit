import { test } from "./browser"
import { expect } from "@playwright/test"
import { deliveries, login, nextCode, open, seed, totp } from "./browser"

test("AK-UI-14: TS contract: strong-factor lifecycle, backup replacement and fresh proof use actual challenges", async ({
  page,
  request,
}) => {
  const who = await seed(request)
  await open(page)
  expect((await login(page, who)).status).toBe("complete")
  const passwordProof = await page.evaluate(
    (password) => window.ak.client.stepUpWithPassword(password),
    who.password
  )
  expect(passwordProof.step_up_required_for_sensitive_actions).toBe(false)
  const beforeContact = (await deliveries(request, who.email)).length
  await page.evaluate(() => window.ak.client.sendContactStepUpCode("email"))
  const contact = await page.evaluate(
    (proof) => window.ak.client.stepUpWithContactCode(proof),
    await nextCode(request, who.email, beforeContact)
  )
  expect(contact.step_up_required_for_sensitive_actions).toBe(false)

  const phone = "+12025550195"
  const beforeSetup = (await deliveries(request, phone)).length
  const smsSetup = await page.evaluate(
    (phoneNumber) =>
      window.ak.client.setupTwoFactor({ method: "sms", phoneNumber }),
    phone
  )
  expect(smsSetup.method).toBe("sms")
  const sms = await page.evaluate(
    ({ phoneNumber, code }) =>
      window.ak.client.addTwoFactorFactor({
        method: "sms",
        phoneNumber,
        code,
        makeDefault: true,
      }),
    { phoneNumber: phone, code: await nextCode(request, phone, beforeSetup) }
  )
  expect(sms.factor).toMatchObject({ method: "sms", is_default: true })
  expect(sms.backup_codes.length).toBeGreaterThan(0)
  const setup = await page.evaluate(() =>
    window.ak.client.setupTwoFactor({ method: "totp" })
  )
  expect(setup.secret).toBeTruthy()
  const app = await page.evaluate(
    (code) => window.ak.client.addTwoFactorFactor({ method: "totp", code }),
    totp(setup.secret!)
  )
  await page.evaluate(
    (id) => window.ak.client.setDefaultTwoFactorFactor(id),
    app.factor.id
  )
  const appDefault = await page.evaluate(() => window.ak.client.getSecurity())
  expect(
    appDefault.two_factor.factors.find((factor) => factor.is_default)?.id
  ).toBe(app.factor.id)
  await page.evaluate(
    (id) => window.ak.client.setDefaultTwoFactorFactor(id),
    sms.factor.id
  )
  await page.evaluate(
    (id) => window.ak.client.removeTwoFactorFactor(id),
    app.factor.id
  )
  const oneFactor = await page.evaluate(() => window.ak.client.getSecurity())
  expect(oneFactor.two_factor.factors.map((factor) => factor.id)).toEqual([
    sms.factor.id,
  ])

  const backup = await page.evaluate(() =>
    window.ak.client.regenerateBackupCodes()
  )
  expect(backup.length).toBeGreaterThan(0)
  expect(new Set(backup).size).toBe(backup.length)
  expect(backup.some((value) => sms.backup_codes.includes(value))).toBe(false)
  await page.evaluate(() => window.ak.client.signOut())
  const challenge = await login(page, who)
  expect(challenge.status).toBe("second_factor_required")
  if (challenge.status !== "second_factor_required")
    throw new Error("missing real second-factor challenge")
  const rejected = await page.evaluate(
    async ({ step, code }) => {
      try {
        await window.ak.client.verifyTwoFactor({
          userId: step.user_id,
          challenge: step.challenge,
          code,
          backupCode: true,
        })
        return null
      } catch (error) {
        return {
          status: (error as { status: number }).status,
          code: (error as { code: string }).code,
        }
      }
    },
    { step: challenge.second_factor, code: sms.backup_codes[0] }
  )
  expect(rejected).toEqual({ status: 401, code: "invalid_code" })
  const signed = await page.evaluate(
    ({ step, code }) =>
      window.ak.client.verifyTwoFactor({
        userId: step.user_id,
        challenge: step.challenge,
        code,
        backupCode: true,
      }),
    { step: challenge.second_factor, code: backup[0] }
  )
  expect(signed.status).toBe("complete")
  await page.evaluate(() => window.ak.client.signOut())

  const later = await login(page, who)
  if (later.status !== "second_factor_required")
    throw new Error("missing subsequent second-factor challenge")
  const beforeSend = (await deliveries(request, phone)).length
  const sent = await page.evaluate(
    ({ step, factor }) =>
      window.ak.client.sendTwoFactorChallenge({
        userId: step.user_id,
        challenge: step.challenge,
        factorId: factor,
      }),
    { step: later.second_factor, factor: sms.factor.id }
  )
  const reused = await page.evaluate(
    async ({ step, code }) => {
      try {
        await window.ak.client.verifyTwoFactor({
          userId: step.user_id,
          challenge: step.challenge,
          code,
          backupCode: true,
        })
        return null
      } catch (error) {
        return (error as { code: string }).code
      }
    },
    { step: sent.second_factor, code: backup[0] }
  )
  expect(reused).toBe("invalid_code")
  const accepted = await page.evaluate(
    ({ step, factor, code }) =>
      window.ak.client.verifyTwoFactor({
        userId: step.user_id,
        challenge: step.challenge,
        factorId: factor,
        code,
      }),
    {
      step: sent.second_factor,
      factor: sms.factor.id,
      code: await nextCode(request, phone, beforeSend),
    }
  )
  expect(accepted.status).toBe("complete")
  const beforeStepUp = (await deliveries(request, phone)).length
  await page.evaluate(
    (factorId) => window.ak.client.sendStepUpCode({ factorId }),
    sms.factor.id
  )
  const fresh = await page.evaluate(
    ({ factorId, code }) =>
      window.ak.client.stepUpWithTwoFactor({ factorId, code }),
    {
      factorId: sms.factor.id,
      code: await nextCode(request, phone, beforeStepUp),
    }
  )
  expect(fresh.step_up_required_for_sensitive_actions).toBe(false)
  await page.evaluate(() => window.ak.client.disableTwoFactor())
  const disabled = await page.evaluate(() => window.ak.client.getSecurity())
  expect(disabled.two_factor.enabled).toBe(false)
  expect(disabled.two_factor.factors).toEqual([])
  expect(disabled.two_factor.backup_codes_remaining).toBe(0)
})

test("AK-UI-15: TS contract: browser-bound access is usable only with its real DPoP proof and not replayable", async ({
  page,
  request,
}) => {
  const who = await seed(request)
  await open(page, "?bound")
  const signed = await login(page, who)
  expect(signed.status).toBe("complete")
  const token = await page.evaluate(() => window.ak.client.getAccessToken())
  expect(token).toBeTruthy()
  const claims = JSON.parse(
    Buffer.from(token!.split(".")[1], "base64url").toString()
  ) as { sub: string; cnf?: { jkt?: string } }
  expect(claims.sub).toBe(who.id)
  expect(claims.cnf?.jkt).toBeTruthy()
  expect(
    (
      await request.get("/api/v1/me", {
        headers: { Authorization: `Bearer ${token}` },
      })
    ).status()
  ).toBe(401)
  const captured = page.waitForRequest(
    (request) =>
      new URL(request.url()).pathname === "/api/v1/me" &&
      request.headers()["x-critical-probe"] === "bound-proof"
  )
  const allowed = await page.evaluate(async () => {
    const response = await window.ak.client.authFetch("/api/v1/me", {
      headers: { "X-Critical-Probe": "bound-proof" },
      cache: "no-store",
    })
    return {
      status: response.status,
      body: (await response.json()) as { id: string },
    }
  })
  expect(allowed.status).toBe(200)
  expect(allowed.body.id).toBe(who.id)
  const actual = await captured
  const headers = await actual.allHeaders()
  expect(headers.authorization).toBe(`DPoP ${token}`)
  expect(headers.dpop).toBeTruthy()
  const replay = await request.get("/api/v1/me", {
    headers: { Authorization: headers.authorization, DPoP: headers.dpop },
  })
  expect(replay.status()).toBe(401)

  // Same-origin native directories have separate cookies and session hints.
  // Their DPoP storage must also remain independent across logout/reload.
  const privateUser = await seed(request, { email: who.email, isolated: true })
  expect(privateUser.id).not.toBe(who.id)
  const privatePage = await page.context().newPage()
  try {
    await open(privatePage, "?bound&isolated")
    expect((await login(privatePage, privateUser)).status).toBe("complete")
    const privateClaims = await privatePage.evaluate(() => {
      const token = window.ak.client.getAccessToken()!
      return JSON.parse(
        atob(token.split(".")[1].replaceAll("-", "+").replaceAll("_", "/"))
      ) as {
        sub: string
        cnf: { jkt: string }
      }
    })
    expect(privateClaims.sub).toBe(privateUser.id)
    expect(privateClaims.cnf.jkt).toBeTruthy()
    await privatePage.evaluate(() => window.ak.client.signOut())
    await expect(privatePage.getByTestId("session-status")).toHaveText(
      "anonymous"
    )

    await page.reload()
    await expect(page.getByTestId("session-user")).toHaveText(who.id)
    expect(
      await page.evaluate(() =>
        window.ak.client.getMe().then((user) => user?.id)
      )
    ).toBe(who.id)
    expect(privateClaims.cnf.jkt).not.toBe(claims.cnf!.jkt)
    await page.evaluate(() => window.ak.client.signOut())
    await page.reload()
    await expect(page.getByTestId("session-status")).toHaveText("anonymous")
    await privatePage.reload()
    await expect(privatePage.getByTestId("session-status")).toHaveText(
      "anonymous"
    )
  } finally {
    await privatePage.close()
  }
})
