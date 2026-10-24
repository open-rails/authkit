import { test } from "./browser"
import { expect } from "@playwright/test"
import {
  code,
  deliveries,
  identity,
  login,
  nextCode,
  open,
  password,
  seed,
} from "./browser"

test("AK-UI-11: TS contract: pending registration availability and authenticated abandonment have observable effects", async ({
  page,
}) => {
  const who = identity()
  await open(page)
  const before = await page.evaluate(
    (who) =>
      window.ak.client.checkAvailability({
        username: `  ${who.username.toUpperCase()}  `,
      }),
    who
  )
  expect(before.username?.available).toBe(true)
  expect(
    await page.evaluate(
      (who) =>
        window.ak.client.register({
          identifier: who.email,
          username: who.username,
          password: who.password,
        }),
      who
    )
  ).toBeNull()
  expect(
    (
      await page.evaluate(
        (who) => window.ak.client.checkAvailability({ username: who.username }),
        who
      )
    ).username?.available
  ).toBe(false)
  await page.evaluate(
    (who) =>
      window.ak.client.abandonRegistration({
        identifier: who.email,
        password: "Wrong-abandon-password-9",
      }),
    who
  )
  expect(
    (
      await page.evaluate(
        (who) => window.ak.client.checkAvailability({ username: who.username }),
        who
      )
    ).username?.available
  ).toBe(false)
  await page.evaluate(
    (who) =>
      window.ak.client.abandonRegistration({
        identifier: who.email,
        password: who.password,
      }),
    who
  )
  expect(
    (
      await page.evaluate(
        (who) => window.ak.client.checkAvailability({ username: who.username }),
        who
      )
    ).username?.available
  ).toBe(true)
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
})

test("AK-UI-12: TS contract: reset, password change, contact proof, passwordless and self-recovery round trip", async ({
  page,
  request,
}) => {
  const who = await seed(request)
  await open(page)
  const beforeReset = (await deliveries(request, who.email)).length
  await page.evaluate(
    (email) => window.ak.client.requestPasswordReset(email),
    who.email
  )
  let resetToken: string | undefined
  await expect
    .poll(async () => {
      resetToken = (await deliveries(request, who.email))
        .slice(beforeReset)
        .findLast((message) => !!message.token)?.token
      return resetToken
    })
    .toBeTruthy()
  const resetPassword = "Reset-native-credential-92"
  await page.evaluate(
    ({ token, newPassword }) =>
      window.ak.client.confirmPasswordReset({ token, newPassword }),
    { token: resetToken!, newPassword: resetPassword }
  )
  const badOld = await page.evaluate(async (who) => {
    try {
      await window.ak.client.signInWithPassword({
        identifier: who.email,
        password: who.password,
      })
      return null
    } catch (error) {
      return (error as { code: string }).code
    }
  }, who)
  expect(badOld).toBe("invalid_credentials")
  expect(
    (await login(page, { email: who.email, password: resetPassword })).status
  ).toBe("complete")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
  const changedPassword = "Changed-native-credential-93"
  await page.evaluate(
    (newPassword) => window.ak.client.changePassword({ newPassword }),
    changedPassword
  )
  const profile = await page.evaluate(() =>
    window.ak.client.request<{ id: string }>("PATCH", "/me", {
      body: { preferred_language: "en" },
    })
  )
  expect(profile.id).toBe(who.id)

  const phone = "+12025550197"
  const beforePhone = (await deliveries(request, phone)).length
  await page.evaluate((phone) => window.ak.client.changePhone(phone), phone)
  await page.evaluate(
    ({ phone, proof }) =>
      window.ak.client.confirmVerification({ identifier: phone, code: proof }),
    { phone, proof: await nextCode(request, phone, beforePhone) }
  )
  const phoneAdded = await page.evaluate(() =>
    window.ak.client.request<{
      id: string
      phone_number: string
      phone_verified: boolean
    }>("GET", "/me")
  )
  expect(phoneAdded).toMatchObject({
    id: who.id,
    phone_number: phone,
    phone_verified: true,
  })
  await page.evaluate(() => window.ak.client.removePhone())
  expect(
    await page.evaluate(() => window.ak.client.request("GET", "/me"))
  ).toMatchObject({ id: who.id, phone_number: null })

  await page.evaluate(() => window.ak.client.signOut())
  const beforePasswordless = (await deliveries(request, who.email)).length
  await page.evaluate(
    (identifier) => window.ak.client.startPasswordless({ identifier }),
    who.email
  )
  const signed = await page.evaluate(
    ({ identifier, proof }) =>
      window.ak.client.confirmPasswordless({ identifier, code: proof }),
    {
      identifier: who.email,
      proof: await nextCode(request, who.email, beforePasswordless),
    }
  )
  expect(signed.status).toBe("complete")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
  expect(
    await page.evaluate(() =>
      window.ak.events.filter((event) => event.kind === "registered")
    )
  ).toEqual([])

  await page.evaluate(() => window.ak.client.deleteAccount())
  const recovery = await login(page, {
    email: who.email,
    password: changedPassword,
  })
  expect(recovery.status).toBe("account_recovery_required")
  if (recovery.status !== "account_recovery_required")
    throw new Error("missing real recovery proof")
  await page.evaluate(
    (token) => window.ak.client.confirmAccountRecovery(token),
    recovery.recovery.token
  )
  expect(
    (await login(page, { email: who.email, password: changedPassword })).status
  ).toBe("complete")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
  await page.evaluate(() => window.ak.client.signOut())
})

test("AK-UI-13: TS contract: phone-only login completes its actual new-device proof", async ({
  page,
  request,
}) => {
  const who = await seed(request, { email: "", phone: "+12025550196" })
  await open(page)
  const result = await login(page, { email: "+12025550196", password })
  expect(result.status).toBe("device_verification_required")
  if (result.status !== "device_verification_required")
    throw new Error("expected a new-device ceremony")
  const step = result.device_verification
  const resent = await page.evaluate(
    (step) =>
      window.ak.client.sendDeviceVerification({
        userId: step.user_id,
        challenge: step.challenge,
        channel: "sms",
      }),
    step
  )
  const delivered = await code(request, "+12025550196", "new_device_code")
  const complete = await page.evaluate(
    ({ step, delivered }) =>
      window.ak.client.confirmDeviceVerification({
        userId: step.user_id,
        challenge: step.challenge,
        code: delivered,
      }),
    { step: resent.device_verification, delivered }
  )
  expect(complete.status).toBe("complete")
  await expect(page.getByTestId("session-user")).toHaveText(who.id)
})
