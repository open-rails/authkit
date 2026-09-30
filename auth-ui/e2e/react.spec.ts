import path from "node:path"

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test"

import { outbox, totp } from "./support/api"

const app = path.resolve(import.meta.dirname, ".react-app/app.js")

async function loadApp(page: Page) {
  await page.route("**/__auth-ui/react-app.js", (route) =>
    route.fulfill({ path: app, contentType: "text/javascript" })
  )
  await page.goto("/")
  await page.addScriptTag({ url: "/__auth-ui/react-app.js", type: "module" })
  await expect(page.getByTestId("status")).toHaveText("anonymous")
}

// Latest code delivered to `to` after `seen` earlier messages.
async function nextCode(request: APIRequestContext, to: string, seen: number) {
  let code: string | undefined
  await expect(async () => {
    const msgs = await outbox(request, to)
    code = msgs.slice(seen).findLast((m) => m.code)?.code
    expect(code).toBeTruthy()
  }).toPass({ timeout: 10_000 })
  return code!
}

test("React hooks: register, TOTP, step-up guarded action, 2FA login", async ({
  page,
  request,
}) => {
  await loadApp(page)
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `react-${id}@example.test`
  const password = "Correct-horse-battery-9"

  // useRegister: register → verify code → signed in.
  await page.getByTestId("reg-identifier").fill(email)
  await page.getByTestId("reg-username").fill(`r${id}`)
  await page.getByTestId("reg-password").fill(password)
  await page.getByRole("button", { name: "register" }).click()
  await page.getByTestId("reg-code").fill(await nextCode(request, email, 0))
  await page.getByRole("button", { name: "verify registration" }).click()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await expect(page.getByTestId("email")).toHaveText(email)

  // useTwoFactorSettings: TOTP enrollment. Codes must come from increasing
  // steps, so start early in one.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()
  await page.getByRole("button", { name: "start totp" }).click()
  const secret = await page.getByTestId("totp-secret").textContent()
  await page.getByTestId("tf-code").fill(totp(secret!, now))
  await page.getByRole("button", { name: "confirm factor" }).click()
  await expect(page.getByTestId("backup-codes")).not.toBeEmpty()
  await page.getByRole("button", { name: "saved them" }).click()
  await expect(page.getByTestId("factors")).toHaveText("totp")

  // A stale session needs a 2FA step-up; the guarded action retries by
  // itself once it succeeds, and the email factor starts with a setup code.
  await request.post(
    `/__test/stale-sessions?email=${encodeURIComponent(email)}`
  )
  // Enrollment verified the session: its refresh still yields a token, not a
  // continuation.
  expect(
    await page.evaluate(() =>
      (
        window as unknown as { authClient: { refresh(): Promise<boolean> } }
      ).authClient.refresh()
    )
  ).toBe(true)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  let seen = (await outbox(request, email)).length
  await page.getByRole("button", { name: "add email factor" }).click()
  await expect(page.getByTestId("stepup-step")).toHaveText("required")
  await expect(page.getByTestId("stepup-methods")).toHaveText("2fa")
  await page.getByTestId("stepup-code").fill("000000")
  await page.getByRole("button", { name: "step up" }).click()
  await expect(page.getByTestId("stepup-error")).not.toBeEmpty()
  await page.getByTestId("stepup-code").fill(totp(secret!, now + 30_000))
  await page.getByRole("button", { name: "step up" }).click()
  await expect(page.getByTestId("stepup-step")).toHaveText("idle")
  const setup = await nextCode(request, email, seen)
  await page
    .getByTestId("tf-code")
    .fill(setup === "000000" ? "111111" : "000000")
  await page.getByRole("button", { name: "confirm factor" }).click()
  await expect(page.getByTestId("tf-error")).toHaveText("invalid_code")
  await page.getByTestId("tf-code").fill(setup)
  await page.getByRole("button", { name: "confirm factor" }).click()
  await expect(page.getByTestId("factors")).toHaveText(
    /totp.*email|email.*totp/
  )
  await expect(page.getByTestId("tf-error")).toBeEmpty()

  // useLogin: password → 2FA → switch to the email factor → verify.
  await page.getByRole("button", { name: "sign out" }).click()
  await expect(page.getByTestId("status")).toHaveText("anonymous")
  await page.getByTestId("login-identifier").fill(email)
  await page.getByTestId("login-password").fill(password)
  await page.getByRole("button", { name: "sign in" }).click()
  await expect(page.getByTestId("login-step")).toHaveText("two_factor")
  await expect(page.getByTestId("login-method")).toHaveText("totp")
  seen = (await outbox(request, email)).length
  await page.getByTestId("factor-email").click()
  await expect(page.getByTestId("login-method")).toHaveText("email")
  const first = await nextCode(request, email, seen)
  // A miss keeps the emailed code: the same code then signs in, no resend.
  await page
    .getByTestId("login-code")
    .fill(first === "000000" ? "111111" : "000000")
  await page.getByRole("button", { name: "verify code" }).click()
  await expect(page.getByTestId("login-error")).toHaveText("invalid_code")
  await page.getByTestId("login-code").fill(first)
  await page.getByRole("button", { name: "verify code" }).click()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await expect(page.getByTestId("email")).toHaveText(email)
  expect((await outbox(request, email)).length).toBe(seen + 1)

  // onSessionChange fired per boundary, not per refresh.
  expect(
    await page.evaluate(
      () => (window as unknown as { sessionChanges: string[] }).sessionChanges
    )
  ).toEqual(["anonymous", "authenticated", "anonymous", "authenticated"])
})
