import { test } from "./browser"
import { expect } from "@playwright/test"
import { code, deliveries, identity, nextCode, open } from "./browser"

test("AK-UI-07: AK-J29-C05: native signup, contact change, MFA login and confirmed deletion use real service state", async ({
  page,
  request,
}) => {
  const who = identity()
  await open(page, "?register")
  await page.getByRole("button", { name: "Open sign in", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.locator('input[name="email"]').fill(who.email)
  await dialog.locator('input[name="username"]').fill(who.username)
  await dialog.locator('input[name="new-password"]').fill(who.password)
  await dialog.getByRole("button", { name: "Register", exact: true }).click()
  await dialog
    .locator('input[autocomplete="one-time-code"]')
    .fill(await code(request, who.email))
  await expect(page.getByTestId("session-status")).toHaveText("authenticated")
  await expect(dialog).not.toBeVisible()
  const userId = await page.getByTestId("session-user").textContent()
  expect(userId).toBeTruthy()

  const newEmail = `new-${who.email}`
  await page
    .getByRole("button", { name: "Change", exact: true })
    .first()
    .click()
  await page.getByLabel("New email address", { exact: true }).fill(newEmail)
  await page.getByRole("button", { name: "Send code", exact: true }).click()
  await page
    .locator('input[autocomplete="one-time-code"]')
    .fill(await code(request, newEmail))
  await expect(page.getByTestId("profile-email")).toHaveText(newEmail)
  await expect(page.getByTestId("session-user")).toHaveText(userId!)
  await page.getByRole("button", { name: "Close", exact: true }).click()

  const phone = "+12025550198"
  const beforeEnrollment = (await deliveries(request, phone)).length
  await page.getByRole("button", { name: "Turn on", exact: true }).click()
  await page.getByRole("radio", { name: /^SMS/ }).check()
  await page.locator('input[autocomplete="tel"]').fill(phone)
  await page.getByRole("button", { name: "Continue", exact: true }).click()
  await page
    .locator('input[autocomplete="one-time-code"]')
    .fill(await nextCode(request, phone, beforeEnrollment))
  await expect(page.getByText("On", { exact: true })).toBeVisible()
  await page
    .getByRole("button", { name: "I've saved my backup codes", exact: true })
    .click()

  await page.getByRole("button", { name: "Sign out", exact: true }).click()
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
  await open(page)
  await page.getByRole("button", { name: "Open sign in", exact: true }).click()
  await dialog.locator('input[name="identifier"]').fill(newEmail)
  await dialog.locator('input[name="password"]').fill(who.password)
  const beforeSignIn = (await deliveries(request, phone)).length
  await dialog.getByRole("button", { name: "Sign in", exact: true }).click()
  await dialog
    .locator('input[autocomplete="one-time-code"]')
    .fill(await nextCode(request, phone, beforeSignIn))
  await expect(page.getByTestId("session-status")).toHaveText("authenticated")
  await expect(page.getByTestId("session-user")).toHaveText(userId!)
  await expect(dialog).not.toBeVisible()
  const token = await page.evaluate(() => window.ak.client.getAccessToken())

  await page
    .getByRole("button", { name: "Delete account", exact: true })
    .click()
  const confirmation = page.getByRole("alertdialog")
  await confirmation.getByLabel("Confirmation", { exact: true }).fill("delete")
  await expect(
    confirmation.getByRole("button", { name: "Delete account", exact: true })
  ).toBeDisabled()
  await confirmation.getByLabel("Confirmation", { exact: true }).fill("DELETE")
  await confirmation
    .getByRole("button", { name: "Delete account", exact: true })
    .click()
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          window.ak.events.filter((event) => event.kind === "deleted").length
      )
    )
    .toBe(1)
  // This read is deliberately stateless and exposes the caller's tombstone;
  // mutation routes require the current live session.
  const tombstone = await request.get("/api/v1/me", {
    headers: { Authorization: `Bearer ${token}` },
  })
  expect(tombstone.status()).toBe(200)
  expect(await tombstone.json()).toMatchObject({
    id: userId,
    deleted_at: expect.any(String),
  })
  const rejected = await request.patch("/api/v1/me", {
    headers: { Authorization: `Bearer ${token}` },
    data: { preferred_language: "en" },
  })
  expect(rejected.status()).toBe(401)
  expect(
    await page.evaluate(() => window.ak.client.getAccessToken())
  ).toBeNull()
})
