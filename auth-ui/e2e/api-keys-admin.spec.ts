import { expect as baseExpect, test } from "@playwright/test"

import {
  addMember,
  hostLocation,
  merchantGroup,
  newUser,
  signedInAt,
} from "./support/admin"

const expect = baseExpect.configure({ timeout: 15_000 })

test("ApiKeysAdmin in a host router: the secret shown once works, revoked keys behind a URL toggle", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const owner = await newUser(browser, request)
  const group = await merchantGroup(request, owner.email)
  const base = `/router/api-keys/${group}`
  const page = await signedInAt(browser, owner, base)
  await expect(page.getByText("No API keys yet.")).toBeVisible()

  await page.getByRole("button", { name: "New key" }).click()
  const dialog = page.getByRole("dialog", { name: "New API key" })
  await dialog.getByLabel("Name").fill("storefront")
  await expect(dialog.getByRole("option", { name: /Owner/ })).toBeEnabled()
  await dialog.getByLabel("Role").selectOption("merchant:viewer")
  await dialog.getByRole("button", { name: "Create key" }).click()
  const secretField = dialog.getByLabel("Secret of storefront")
  await expect(secretField).not.toHaveValue("")
  const secret = await secretField.inputValue()
  await dialog.getByRole("button", { name: "Close" }).first().click()
  const table = page.getByRole("table", { name: "API keys" })
  await expect(table.getByRole("row", { name: /storefront/ })).toContainText(
    "Viewer"
  )
  await expect(page.getByText(secret)).toHaveCount(0)
  await page.getByRole("button", { name: "New key" }).click()
  await expect(page.getByRole("dialog").getByLabel(/^Secret of/)).toHaveCount(0)
  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click()

  // The key acts with its role: a viewer reads the members.
  const members = await request.get(`/api/v1/groups/${group}/members`, {
    headers: { Authorization: `Bearer ${secret}` },
  })
  expect(members.status()).toBe(200)

  await table.getByRole("button", { name: "Revoke: storefront" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Revoke" })
    .click()
  await expect(page.getByText("storefront was revoked.")).toBeVisible()
  await expect(page.getByText("No API keys yet.")).toBeVisible()
  // The toggle follows the host router's URL, which updates after the click.
  await page.getByLabel("Show revoked keys").click()
  await expect(page.getByLabel("Show revoked keys")).toBeChecked()
  await expect(hostLocation(page)).toHaveText(`${base}?revoked=1`)
  await expect(table.getByRole("row", { name: /storefront/ })).toContainText(
    "Revoked"
  )
  const refused = await request.get(`/api/v1/groups/${group}/members`, {
    headers: { Authorization: `Bearer ${secret}` },
  })
  expect(refused.status()).toBe(401)
  await page.context().close()
})

test("ApiKeysAdmin alone: read-only and no-access states", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const [owner, staff, viewer] = await Promise.all(
    [0, 1, 2].map(() => newUser(browser, request))
  )
  const group = await merchantGroup(request, owner.email)
  await addMember(request, group, staff.email, "staff")
  await addMember(request, group, viewer.email, "viewer")
  const base = `/alone/api-keys/${group}`
  const minter = await signedInAt(browser, owner, base)
  await minter.getByRole("button", { name: "New key" }).click()
  await minter.getByRole("dialog").getByLabel("Name").fill("reporting")
  await minter
    .getByRole("dialog")
    .getByRole("button", { name: "Create key" })
    .click()
  await expect(
    minter.getByRole("dialog").getByLabel("Secret of reporting")
  ).toBeVisible()
  await minter.context().close()

  const reader = await signedInAt(browser, viewer, base)
  await expect(
    reader.getByRole("table", { name: "API keys" }).getByText("reporting")
  ).toBeVisible()
  await expect(reader.getByRole("button", { name: "New key" })).toHaveCount(0)
  await expect(reader.getByRole("button", { name: /^Revoke/ })).toHaveCount(0)
  await reader.context().close()

  const outsider = await signedInAt(browser, staff, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await outsider.context().close()
})
