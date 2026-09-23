import path from "node:path"

import {
  expect as baseExpect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test"

import { outbox, registerVerified, totp } from "./support/api"

// Password hashing is slow on a loaded CI box.
const expect = baseExpect.configure({ timeout: 15_000 })

const app = path.resolve(import.meta.dirname, ".react-app/account.js")
const font = path.resolve(
  import.meta.dirname,
  "../node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2"
)

async function route(page: Page) {
  await page.route("**/__auth-ui/account-app.js", (r) =>
    r.fulfill({ path: app, contentType: "text/javascript" })
  )
  await page.route("**/__auth-ui/inter.woff2", (r) =>
    r.fulfill({ path: font, contentType: "font/woff2" })
  )
}

// (Re)loads the host page; the refresh cookie restores any session.
async function loadApp(page: Page, query = "") {
  await page.goto(`/${query}`)
  await page.addScriptTag({ url: "/__auth-ui/account-app.js", type: "module" })
  await expect(page.getByTestId("status")).not.toHaveText("loading")
}

async function signIn(page: Page, identifier: string, password: string) {
  await expect(page.getByTestId("status")).toHaveText("anonymous")
  await page.getByLabel("identifier").fill(identifier)
  await page.getByLabel("password").fill(password)
  await page.getByRole("button", { name: "sign in" }).click()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
}

async function nextCode(request: APIRequestContext, to: string, seen = 0) {
  let code: string | undefined
  await expect(async () => {
    code = (await outbox(request, to)).slice(seen).findLast((m) => m.code)?.code
    expect(code).toBeTruthy()
  }).toPass({ timeout: 10_000 })
  return code!
}

// TOTP codes are single-use per step: wait for a step after `used`.
async function laterStep(page: Page, used: number) {
  const step = Math.floor(used / 30_000)
  if (Math.floor(Date.now() / 30_000) === step)
    await page.waitForTimeout((step + 1) * 30_000 - Date.now() + 300)
}

// Waits until a TOTP step boundary is at least `margin` ms away.
async function freshTotpStep(page: Page, margin = 8_000) {
  const into = Date.now() % 30_000
  if (into > 30_000 - margin) await page.waitForTimeout(30_300 - into)
}

test("account panels: password, TOTP, backup codes, email, sessions, delete", async ({
  page,
  request,
  context,
}) => {
  test.setTimeout(180_000)
  await route(page)
  await page.goto("/")
  const { email, password } = await registerVerified(page, request)
  await context.clearCookies()

  await loadApp(page)
  await signIn(page, email, password)
  const card = (name: string) =>
    page.locator('[data-slot="card"]', { hasText: name })
  await expect(card("Contact details")).toContainText(email)

  // Password change on a stale session: the step-up dialog asks for the
  // current password, then the change retries by itself.
  await request.post(
    `/__test/stale-sessions?email=${encodeURIComponent(email)}`
  )
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  const newPassword = "Brand-new-horse-battery-7"
  await page.getByRole("button", { name: "Change password" }).click()
  const pwDialog = page.getByRole("dialog", { name: "Change password" })
  await pwDialog.getByLabel("New password").fill(newPassword)
  await pwDialog.getByLabel("Confirm password").fill(newPassword)
  await pwDialog.getByRole("button", { name: "Update password" }).click()
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await stepUp.waitFor()
  await stepUp.getByLabel("Password", { exact: true }).fill("wrong-password-1")
  await stepUp.getByRole("button", { name: "Confirm" }).click()
  await expect(stepUp.getByRole("alert")).toBeVisible()
  await stepUp.getByLabel("Password", { exact: true }).fill(password)
  await stepUp.getByRole("button", { name: "Confirm" }).click()
  await expect(stepUp).toBeHidden()
  await expect(page.getByText("Password updated successfully!")).toBeVisible()
  // TOTP enrollment: QR + setup key, code auto-submits, backup codes shown once.
  const tf = card("Two-factor authentication")
  await tf.getByRole("button", { name: "Turn on" }).click()
  await tf.getByRole("radio", { name: /Authenticator app/ }).check()
  await freshTotpStep(page)
  await tf.getByRole("button", { name: "Continue" }).click()
  await expect(tf.getByText(/Scan this with/)).toBeVisible()
  const secret = (await tf.getByLabel("Setup key").textContent())!.replace(
    /\s/g,
    ""
  )
  const enrolledAt = Date.now()
  await tf
    .getByRole("textbox", { name: "Verification code" })
    .fill(totp(secret, enrolledAt))
  const codes = tf.getByRole("list", { name: "Backup codes" })
  await expect(codes.getByRole("listitem")).not.toHaveCount(0)
  const firstCodes = await codes.getByRole("listitem").allTextContents()
  await tf.getByRole("button", { name: "I've saved my backup codes" }).click()
  await expect(tf.getByText("On", { exact: true })).toBeVisible()
  await expect(tf.getByText("Authenticator app", { exact: true })).toBeVisible()

  // Sign in again with the new factor, then come back later: regenerating
  // codes on the stale session needs a 2FA step-up.
  await page.evaluate(() =>
    (document.querySelector("button[hidden]") as HTMLButtonElement).click()
  )
  await expect(page.getByTestId("status")).toHaveText("anonymous")
  await page.getByLabel("identifier").fill(email)
  await page.getByLabel("password").fill(newPassword)
  await page.getByRole("button", { name: "sign in" }).click()
  await laterStep(page, enrolledAt)
  const loggedInAt = Date.now()
  await page.getByLabel("2fa code").fill(totp(secret, loggedInAt))
  await page.getByRole("button", { name: "verify" }).click()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await request.post(
    `/__test/stale-sessions?email=${encodeURIComponent(email)}`
  )
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await tf.getByRole("button", { name: "Generate new codes" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Generate new codes" })
    .click()
  await expect(stepUp).toBeVisible()
  await laterStep(page, loggedInAt)
  await stepUp
    .getByRole("textbox", { name: "Verification code" })
    .fill(totp(secret))
  await expect(stepUp).toBeHidden()
  await expect(codes.getByRole("listitem")).not.toHaveCount(0)
  const backupCodes = await codes.getByRole("listitem").allTextContents()
  expect(backupCodes).not.toEqual(firstCodes)
  await tf.getByRole("button", { name: "I've saved my backup codes" }).click()

  // Email change: a code goes to the new address.
  const contact = card("Contact details")
  const newEmail = email.replace("e2e-", "moved-")
  await contact.getByRole("button", { name: "Change" }).first().click()
  await contact.getByLabel("New email address").fill(newEmail)
  await contact.getByRole("button", { name: "Send code" }).click()
  await expect(
    contact.getByText(`Enter the code we sent to ${newEmail}.`)
  ).toBeVisible()
  await contact
    .getByRole("textbox", { name: "Verification code" })
    .fill(await nextCode(request, newEmail))
  await expect(contact.getByText("Email changed successfully!")).toBeVisible()
  await expect(contact).toContainText(newEmail)

  // Two more signed-in devices (new password + backup codes), then the
  // sessions panel: this device first; revoke one selected, then the rest.
  for (const code of backupCodes.slice(0, 2)) {
    const first = await request.post("/api/v1/password/login", {
      data: { identifier: newEmail, password: newPassword },
    })
    const { metadata } = (await first.json()).error
    const second = await request.post("/api/v1/2fa/verify", {
      data: {
        user_id: metadata.user_id,
        challenge: metadata.challenge,
        code,
        backup_code: true,
      },
    })
    expect(second.status()).toBe(200)
  }
  const sessions = card("Active sessions")
  const rows = sessions
    .getByRole("list", { name: "Active sessions" })
    .getByRole("listitem")
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await expect(rows.first()).toContainText("This device")
  const before = await rows.count()
  expect(before).toBeGreaterThanOrEqual(3)
  await rows.nth(1).getByRole("checkbox").check()
  await sessions.getByRole("button", { name: "Sign out selected (1)" }).click()
  await expect(rows).toHaveCount(before - 1)
  await sessions
    .getByRole("button", { name: "Sign out of all other sessions" })
    .click()
  await expect(rows).toHaveCount(1)
  await expect(
    sessions.getByText("You're not signed in anywhere else.")
  ).toBeVisible()

  // Delete: typed confirmation, then the host hears about it.
  await card("Danger zone")
    .getByRole("button", { name: "Delete account" })
    .click()
  const confirm = page.getByRole("alertdialog")
  await expect(
    confirm.getByRole("button", { name: "Delete account" })
  ).toBeDisabled()
  await confirm.getByLabel("Confirmation").fill("DELETE")
  await confirm.getByRole("button", { name: "Delete account" }).click()
  await expect(page.getByTestId("status")).toHaveText("anonymous")
  expect(
    await page.evaluate(
      () => (window as unknown as { authEvents: string[] }).authEvents
    )
  ).toContain("deleted")
})

// Enrolling a factor verifies the enrolling session (AuthKit v0.131): a reload
// refreshes straight back to "authenticated". Wrong email codes are retryable.
test("TOTP and email 2FA keep the session; wrong email codes retry", async ({
  page,
  request,
  context,
}) => {
  test.setTimeout(120_000)
  await route(page)
  await page.goto("/")
  const { email, password } = await registerVerified(page, request)
  await context.clearCookies()
  await loadApp(page)
  await signIn(page, email, password)
  const tf = page.locator('[data-slot="card"]', {
    hasText: "Two-factor authentication",
  })
  const codeBox = tf.getByRole("textbox", { name: "Verification code" })
  const wrongFor = (code: string) => (code === "000000" ? "111111" : "000000")

  await tf.getByRole("button", { name: "Turn on" }).click()
  await tf.getByRole("radio", { name: /Authenticator app/ }).check()
  await freshTotpStep(page)
  await tf.getByRole("button", { name: "Continue" }).click()
  const secret = (await tf.getByLabel("Setup key").textContent())!.replace(
    /\s/g,
    ""
  )
  await codeBox.fill(totp(secret))
  await tf.getByRole("button", { name: "I've saved my backup codes" }).click()
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await expect(tf.getByText("On", { exact: true })).toBeVisible()

  // Email factor: start sends a setup code; a wrong one keeps the input.
  const seen = (await outbox(request, email)).length
  await tf.getByRole("button", { name: "Add a method" }).click()
  await tf.getByRole("radio", { name: /Email/ }).check()
  await tf.getByRole("button", { name: "Continue" }).click()
  await expect(
    tf.getByText(`Enter the code we sent to ${email}.`)
  ).toBeVisible()
  const setupCode = await nextCode(request, email, seen)
  await codeBox.fill(wrongFor(setupCode))
  await expect(tf.getByText("Invalid verification code.")).toBeVisible()
  await expect(tf.getByRole("button", { name: "Send a new code" })).toHaveCount(
    0
  )
  await expect(codeBox).toBeEnabled()
  await codeBox.fill(setupCode)
  await expect(tf.getByText("Email", { exact: true })).toBeVisible()
  expect((await outbox(request, email)).length).toBe(seen + 1)
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")

  // Email step-up on a stale session: wrong code, then the same sent code.
  await request.post(
    `/__test/stale-sessions?email=${encodeURIComponent(email)}`
  )
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await tf.getByRole("button", { name: "Generate new codes" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Generate new codes" })
    .click()
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await stepUp.getByRole("tab", { name: "Email" }).click()
  const sentBefore = (await outbox(request, email)).length
  await stepUp.getByRole("button", { name: "Send code" }).click()
  const stepUpCode = await nextCode(request, email, sentBefore)
  const stepUpBox = stepUp.getByRole("textbox", { name: "Verification code" })
  await stepUpBox.fill(wrongFor(stepUpCode))
  await expect(stepUp.getByText("Invalid verification code.")).toBeVisible()
  await expect(
    stepUp.getByRole("button", { name: "Send a new code" })
  ).toHaveCount(0)
  await expect(stepUpBox).toBeEnabled()
  await stepUpBox.fill(stepUpCode)
  await expect(stepUp).toBeHidden()
  await expect(
    tf.getByRole("list", { name: "Backup codes" }).getByRole("listitem")
  ).not.toHaveCount(0)
  expect((await outbox(request, email)).length).toBe(sentBefore + 1)
})

for (const theme of ["light", "dark"] as const) {
  for (const [device, viewport] of [
    ["desktop", { width: 1280, height: 900 }],
    ["mobile", { width: 390, height: 844 }],
  ] as const) {
    test(`AccountSecurity screenshot: ${theme} ${device}`, async ({
      page,
      request,
      context,
    }) => {
      await page.setViewportSize(viewport)
      await route(page)
      await page.goto("/")
      const { email, password } = await registerVerified(
        page,
        request,
        `shot_${theme}_${device}`
      )
      await context.clearCookies()
      await loadApp(page, `?theme=${theme}`)
      await signIn(page, email, password)
      await expect(page.getByText("This device")).toBeVisible()
      await expect(page.getByText("Off", { exact: true })).toBeVisible()
      await page.evaluate(async () => {
        await document.fonts.load('16px "Inter Variable"')
        await document.fonts.ready
      })
      await expect(page).toHaveScreenshot(`account-${theme}-${device}.png`, {
        fullPage: true,
        animations: "disabled",
        caret: "hide",
        maxDiffPixelRatio: 0.01,
      })
    })
  }
}
