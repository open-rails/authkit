import path from "node:path"

import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test"

import { outbox, totp } from "./support/api"

const app = path.resolve(import.meta.dirname, ".react-app/sign-in.js")
const password = "Correct-horse-battery-9"

async function loadApp(page: Page, url = "/") {
  await page.route("**/__auth-ui/sign-in.js", (route) =>
    route.fulfill({ path: app, contentType: "text/javascript" })
  )
  await page.goto(url)
  await page.addScriptTag({ url: "/__auth-ui/sign-in.js", type: "module" })
}

async function nextCode(request: APIRequestContext, to: string, seen: number) {
  let code: string | undefined
  await expect(async () => {
    code = (await outbox(request, to)).slice(seen).findLast((m) => m.code)?.code
    expect(code).toBeTruthy()
  }).toPass({ timeout: 10_000 })
  return code!
}

const dialog = (page: Page) => page.getByRole("dialog")
// The visible tab; the other stays mounted but hidden.
const panel = (page: Page) => dialog(page).getByRole("tabpanel")
const codeInput = (page: Page) =>
  dialog(page).getByRole("textbox", { name: "Verification code" })

async function openDialog(page: Page) {
  await page.getByRole("button", { name: "open sign in" }).click()
  await expect(dialog(page)).toBeVisible()
  // Capabilities loaded: the configured provider renders.
  await expect(
    dialog(page)
      .getByRole("button", { name: /with GitHub/ })
      .first()
  ).toBeVisible()
}

async function signIn(page: Page, email: string, pass = password) {
  await openDialog(page)
  await panel(page).getByLabel("Email or phone number").fill(email)
  await panel(page).getByLabel("Password", { exact: true }).fill(pass)
  await panel(page)
    .getByRole("button", { name: "Sign in", exact: true })
    .click()
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "sign out" }).click()
  await expect(page.getByTestId("status")).toHaveText("anonymous")
}

test("register, verify, then TOTP and backup-code sign-in", async ({
  page,
  request,
}) => {
  await loadApp(page)
  await expect(page.getByTestId("status")).toHaveText("anonymous")
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `signin-${id}@example.test`

  // Register → verify code → signed in, dialog closes itself.
  await openDialog(page)
  await dialog(page).getByRole("tab", { name: "Create account" }).click()
  await expect(panel(page)).toHaveCount(1)
  await panel(page).getByLabel("Email or phone number").fill(email)
  await panel(page).getByLabel("Username").fill(`s${id}`)
  await panel(page).getByLabel("Password", { exact: true }).fill(password)
  await panel(page).getByRole("button", { name: "Register" }).click()
  await expect(
    dialog(page).getByRole("heading", { name: "Verify your email" })
  ).toBeVisible()
  await codeInput(page).fill(await nextCode(request, email, 0))
  await expect(dialog(page)).toBeHidden()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await expect(page.getByTestId("email")).toHaveText(email)

  // Enroll TOTP through the client; codes need increasing steps, so start
  // early in one.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()
  const secret = await page.evaluate(async () => {
    const c = (window as unknown as { authClient: AuthClientLike }).authClient
    const out = await c.enableTwoFactor({ method: "totp" })
    return out.secret!
  })
  const backupCodes = await page.evaluate(
    async (code) => {
      const c = (window as unknown as { authClient: AuthClientLike }).authClient
      return (await c.enableTwoFactor({ method: "totp", code })).backupCodes!
    },
    totp(secret, now)
  )
  expect(backupCodes.length).toBeGreaterThan(0)
  await signOut(page)

  // Password → TOTP challenge → wrong code → right code.
  await signIn(page, email)
  await expect(
    dialog(page).getByRole("heading", { name: "Verify it's you" })
  ).toBeVisible()
  await expect(dialog(page).getByRole("tablist")).toHaveCount(0)
  const right = totp(secret, now + 30_000)
  const wrong = ["000000", "111111"].find(
    (c) => c !== right && c !== totp(secret, now)
  )!
  await codeInput(page).fill(wrong)
  await expect(dialog(page).getByRole("alert")).toContainText(
    "Invalid verification code."
  )
  // TOTP codes are not burned: no resend offer.
  await expect(
    dialog(page).getByRole("button", { name: "Send a new code" })
  ).toHaveCount(0)
  await codeInput(page).fill(right)
  await expect(dialog(page)).toBeHidden()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await signOut(page)

  // Backup code instead of the authenticator.
  await signIn(page, email)
  await dialog(page).getByRole("button", { name: "Use a backup code" }).click()
  await dialog(page).getByLabel("Backup codes").fill(backupCodes[0])
  await dialog(page)
    .getByRole("button", { name: "Verify", exact: true })
    .click()
  await expect(dialog(page)).toBeHidden()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  expect(
    await page.evaluate(
      () => (window as unknown as { signedIn: unknown[] }).signedIn.length
    )
  ).toBe(3)
})

test("forgot password, reset from the link, sign in with it", async ({
  page,
  request,
}) => {
  await loadApp(page)
  const id = `${Date.now()}${Math.floor(Math.random() * 1e6)}`
  const email = `reset-${id}@example.test`
  await page.evaluate(
    async (input) => {
      const c = (window as unknown as { authClient: AuthClientLike }).authClient
      await c.register(input)
    },
    { identifier: email, username: `r${id}`, password }
  )
  await page.evaluate(
    async (input) => {
      const c = (window as unknown as { authClient: AuthClientLike }).authClient
      await c.confirmVerification(input)
      await c.signOut()
    },
    { identifier: email, code: await nextCode(request, email, 0) }
  )
  await expect(page.getByTestId("status")).toHaveText("anonymous")

  await openDialog(page)
  await panel(page).getByLabel("Email or phone number").fill(email)
  await panel(page).getByRole("button", { name: "Forgot password?" }).click()
  await expect(dialog(page).getByLabel("Email or phone number")).toHaveValue(
    email
  )
  const seen = (await outbox(request, email)).length
  await dialog(page).getByRole("button", { name: "Send reset link" }).click()
  await expect(
    dialog(page).getByRole("heading", { name: "Check your email" })
  ).toBeVisible()
  let link = ""
  await expect(async () => {
    link =
      (await outbox(request, email)).slice(seen).findLast((m) => m.link)
        ?.link ?? ""
    expect(link).toContain("token=")
  }).toPass({ timeout: 10_000 })

  const next = "Brand-new-password-7"
  await loadApp(page, `/?page=reset${new URL(link).hash}`)
  await page.getByLabel("New password").fill(next)
  await page.getByLabel("Confirm password").fill("mismatch")
  await page.getByRole("button", { name: "Reset password" }).click()
  await expect(page.getByText("Passwords don't match")).toBeVisible()
  await page.getByLabel("Confirm password").fill(next)
  await page.getByRole("button", { name: "Reset password" }).click()
  await expect(
    page.getByRole("heading", { name: "Password reset successful" })
  ).toBeVisible()

  await loadApp(page)
  await signIn(page, email, password)
  await expect(dialog(page).getByRole("alert")).toContainText(
    "Wrong email or password."
  )
  await panel(page).getByLabel("Password", { exact: true }).fill(next)
  await panel(page)
    .getByRole("button", { name: "Sign in", exact: true })
    .click()
  await expect(page.getByTestId("status")).toHaveText("authenticated")
})

test("keyboard order: fields, submit, then providers", async ({ page }) => {
  await loadApp(page)
  await openDialog(page)
  const d = panel(page)
  await expect(d.getByLabel("Email or phone number")).toBeFocused()
  const order = [
    d.getByLabel("Password", { exact: true }),
    d.getByRole("button", { name: "Forgot password?" }),
    d.getByRole("button", { name: "Sign in", exact: true }),
    d.getByRole("button", { name: "Continue with GitHub" }),
    d.getByRole("button", { name: "Continue with Solana" }),
  ]
  for (const next of order) {
    await page.keyboard.press("Tab")
    await expect(next).toBeFocused()
  }

  await dialog(page).getByRole("tab", { name: "Create account" }).click()
  await expect(panel(page)).toHaveCount(1)
  await panel(page).getByLabel("Email or phone number").focus()
  for (const next of [
    d.getByLabel("Username"),
    d.getByLabel("Password", { exact: true }),
    d.getByRole("button", { name: "Register" }),
    d.getByRole("button", { name: "Sign up with GitHub" }),
    d.getByRole("button", { name: "Sign up with Solana" }),
  ]) {
    await page.keyboard.press("Tab")
    await expect(next).toBeFocused()
  }
})

test("OIDC callback reports a provider error", async ({ page }) => {
  await loadApp(page, "/?page=callback#error=access_denied&flow=login")
  await expect(
    page.getByRole("heading", { name: "Sign-in failed" })
  ).toBeVisible()
  await expect(page.getByText("Sign-in was cancelled.")).toBeVisible()
  await loadApp(page, "/?page=callback")
  await expect(page.getByTestId("navigated")).toHaveText("/")
})

for (const theme of ["light", "dark"] as const) {
  for (const [device, viewport] of [
    ["desktop", { width: 1280, height: 800 }],
    ["mobile", { width: 390, height: 844 }],
  ] as const) {
    test(`SignInDialog ${theme} ${device}`, async ({ page }) => {
      await page.setViewportSize(viewport)
      await loadApp(page, `/?theme=${theme}&open=1`)
      await expect(
        dialog(page).getByRole("button", { name: "Continue with GitHub" })
      ).toBeVisible()
      await expect(
        panel(page).getByLabel("Email or phone number")
      ).toBeFocused()
      await expect(page).toHaveScreenshot(
        `sign-in-dialog-${theme}-${device}.png`,
        {
          animations: "disabled",
          caret: "hide",
          maxDiffPixelRatio: 0.01,
        }
      )
    })
  }
}

type AuthClientLike = {
  enableTwoFactor(input: {
    method: string
    code?: string
  }): Promise<{ secret?: string; backupCodes?: string[] }>
  register(input: {
    identifier: string
    username: string
    password: string
  }): Promise<unknown>
  confirmVerification(input: {
    identifier: string
    code: string
  }): Promise<unknown>
  signOut(): Promise<void>
}
