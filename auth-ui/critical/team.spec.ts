import { test } from "./browser"
import { expect } from "@playwright/test"
import {
  code,
  deliveries,
  enrollRequired,
  identity,
  login,
  open,
  seed,
  totp,
} from "./browser"

test("AK-UI-22: the setup link a fresh deployment logs creates the owner, who enrolls a second factor, once", async ({
  page,
  request,
}) => {
  const logged = await request.get("/__fixture/setup-link")
  expect(logged.status()).toBe(200)
  const link = new URL(((await logged.json()) as { url: string }).url)
  expect(link.pathname).toBe("/setup")
  const token = new URLSearchParams(link.hash.slice(1)).get("token")
  expect(token).toBeTruthy()

  await page.goto(`/setup?firstrun&owner-setup${link.hash}`)
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
  const owner = identity()
  await page
    .getByRole("textbox", { name: "Email", exact: true })
    .fill(owner.email)
  await page
    .getByRole("textbox", { name: "Username", exact: true })
    .fill(owner.username)
  await page.getByLabel("Password", { exact: true }).fill(owner.password)
  await page
    .getByLabel("Confirm password", { exact: true })
    .fill(owner.password)
  await page
    .getByRole("button", { name: "Create owner account", exact: true })
    .click()

  // The owner role needs a second factor before any session exists.
  await page.getByRole("radio", { name: /^Authenticator app/ }).check()
  await page
    .getByRole("button", { name: "Set up authenticator", exact: true })
    .click()
  await page
    .getByRole("button", { name: "Show manual setup key", exact: true })
    .click()
  const secret = await page.locator('code[aria-label="Setup key"]').innerText()
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
  await page
    .locator('input[autocomplete="one-time-code"]')
    .fill(totp(secret.trim()))
  await page
    .getByRole("button", { name: "I've saved my backup codes", exact: true })
    .click()
  await expect(page.getByTestId("session-status")).toHaveText("authenticated")
  await expect
    .poll(() =>
      page.evaluate(() =>
        window.ak.events.some((event) => event.kind === "owner-ready")
      )
    )
    .toBe(true)
  const ownerId = await page.getByTestId("session-user").textContent()
  const members = await page.evaluate(() => window.ak.admin.listMembers("root"))
  expect(members.data.map((m) => [m.subject.id, m.role])).toEqual([
    [ownerId, "root:owner"],
  ])

  // Spent, the link creates nobody else.
  const again = await page.evaluate(
    ({ token, password }) =>
      window.ak.client
        .completeSetup({
          token,
          email: "second-owner@example.test",
          username: "secondowner",
          password,
        })
        .then(
          () => null,
          (err: { code?: string }) => err.code
        ),
    { token: token!, password: owner.password }
  )
  expect(again).toBe("setup_link_invalid")
})

test("AK-UI-23: the Team page invites by email, the invitee signs up into the role, and the inviter changes and removes it and revokes a link", async ({
  page,
  browser,
  request,
}, info) => {
  const operator = await seed(request, { rootRole: "operator" })
  await open(page, "?admin-group=root")
  const signedIn = await login(page, operator)
  expect(signedIn.status).toBe("enrollment_required")
  if (signedIn.status !== "enrollment_required")
    throw new Error("operator needs MFA")
  await enrollRequired(page, signedIn.enrollment.token_set)

  await page.getByRole("link", { name: "Invitations", exact: true }).click()
  const invitee = identity()
  await page
    .getByRole("textbox", { name: "Email", exact: true })
    .fill(invitee.email)
  await page
    .getByRole("combobox", { name: "Role", exact: true })
    .selectOption("root:reader")
  const invite = page.getByRole("button", { name: "Invite", exact: true })
  await invite.click()
  await expect(
    page.getByText(`An invitation went to ${invitee.email}.`, { exact: true })
  ).toBeVisible()
  const sent = page.getByRole("table", { name: "Sent invitations" })
  await expect(sent.getByRole("row").nth(1)).toContainText(invitee.email)
  await expect(sent.getByRole("row").nth(1)).toContainText("Pending")

  let emailed: string | undefined
  await expect
    .poll(
      async () =>
        (emailed = (await deliveries(request, invitee.email)).findLast(
          (m) => m.kind === "invite"
        )?.link)
    )
    .toBeTruthy()

  const context = await browser.newContext({
    baseURL: process.env.E2E_BASE_URL,
  })
  const guest = await context.newPage()
  const methods = new Set<string>()
  await guest.exposeFunction("__criticalMethod", (method: string) => {
    methods.add(method)
  })
  try {
    // The invitee signs up with the emailed link and holds its role.
    await guest.goto(`/invite?accept-invitation${new URL(emailed!).hash}`)
    await expect(
      guest.getByRole("heading", { name: "You're invited", exact: true })
    ).toBeVisible()
    await guest.locator('input[name="email"]').fill(invitee.email)
    await guest.locator('input[name="username"]').fill(invitee.username)
    await guest.locator('input[name="new-password"]').fill(invitee.password)
    await guest.getByRole("button", { name: "Register", exact: true }).click()
    await guest
      .locator('input[autocomplete="one-time-code"]')
      .fill(await code(request, invitee.email))
    await expect(
      guest.getByText("Invitation accepted", { exact: true })
    ).toBeVisible()
    await expect(guest.getByTestId("session-status")).toHaveText(
      "authenticated"
    )

    // The inviter sees the member, changes the role, then removes it.
    await page
      .getByLabel("Members and invitations")
      .getByRole("link", { name: "Members", exact: true })
      .click()
    const role = page.getByRole("combobox", {
      name: `Role of ${invitee.username}`,
    })
    await expect(role).toHaveValue("root:reader")
    await role.selectOption("root:auditor")
    await expect(
      page.getByText(`${invitee.username} now holds Auditor.`, { exact: true })
    ).toBeVisible()
    await page
      .getByRole("button", { name: `Remove: ${invitee.username}`, exact: true })
      .click()
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Remove", exact: true })
      .click()
    await expect(
      page.getByText(`${invitee.username} was removed.`, { exact: true })
    ).toBeVisible()
    await expect(role).not.toBeVisible()

    // A revoked link admits nobody, signed in or not.
    await page.getByRole("link", { name: "Invitations", exact: true }).click()
    await page
      .getByRole("combobox", { name: "Role", exact: true })
      .selectOption("root:reader")
    await invite.click()
    const shared = page.getByRole("textbox", {
      name: "Invitation link",
      exact: true,
    })
    await expect(shared).not.toHaveValue("")
    const linkHash = new URL(await shared.inputValue()).hash
    const newest = sent.getByRole("row").nth(1)
    await expect(newest).toContainText("Anyone with the link")
    await newest.getByRole("button", { name: "Revoke", exact: true }).click()
    await page
      .getByRole("alertdialog")
      .getByRole("button", { name: "Revoke", exact: true })
      .click()
    await expect(newest).toContainText("Revoked")
    // Another query, so the page loads anew rather than only its fragment.
    await guest.goto(`/invite?accept-invitation&link${linkHash}`)
    await guest
      .getByRole("button", { name: "Accept invitation", exact: true })
      .click()
    await expect(
      guest.getByText("The invitation was revoked.", { exact: true })
    ).toBeVisible()
  } finally {
    await context.close()
  }
  await info.attach("public-client-invocations", {
    body: JSON.stringify({ methods: [...methods].sort() }),
    contentType: "application/json",
  })
})
