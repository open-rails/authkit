import { expect as baseExpect, test } from "@playwright/test"

import {
  addMember,
  hostLocation,
  merchantGroup,
  newUser,
  signedInAt,
  staleSessions,
} from "./support/admin"

const expect = baseExpect.configure({ timeout: 15_000 })

test("OAuthClientsAdmin in a host router: register, edit, disable, rotate, delete, with a step-up", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const owner = await newUser(browser, request)
  const group = await merchantGroup(request, owner.email)
  const base = `/router/oauth-clients/${group}`
  const page = await signedInAt(browser, owner, base)
  await expect(page.getByText("No clients yet.")).toBeVisible()

  // A client's changes need a recent sign-in: a stale one steps up first.
  await staleSessions(request, owner.email)
  await page.reload()
  await page.getByRole("link", { name: "host: new" }).click()
  await page.getByLabel("Name").fill("Shop")
  await page
    .getByLabel("Redirect URIs, one per line", { exact: true })
    .fill("https://shop.example/callback")
  await page.getByRole("button", { name: "Register client" }).click()
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await stepUp.getByLabel("Password").fill(owner.password)
  await stepUp.getByRole("button", { name: "Confirm" }).click()

  const first = page.getByLabel("Client secret of Shop")
  await expect(first).not.toHaveValue("")
  const secret = await first.inputValue()
  await expect(hostLocation(page)).toHaveText(new RegExp(`^${base}/[^/]+$`))
  const detail = (await hostLocation(page).textContent())!

  await page
    .getByLabel("Redirect URIs, one per line", { exact: true })
    .fill("https://shop.example/callback\nhttps://shop.example/other")
  await page.getByRole("button", { name: "Save" }).click()
  await expect(page.getByText("Shop was saved.")).toBeVisible()
  await page.getByRole("button", { name: "Disable" }).click()
  await expect(page.getByRole("button", { name: "Enable" })).toBeVisible()

  await page.getByRole("button", { name: "New secret" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "New secret" })
    .click()
  await expect(page.getByLabel("Client secret of Shop")).not.toHaveValue(secret)

  // Back to the list, and back again through the host router's history.
  await page.getByRole("link", { name: "Back" }).click()
  await expect(hostLocation(page)).toHaveText(base)
  await expect(
    page.getByRole("table", { name: "OAuth clients" }).getByText("Disabled")
  ).toBeVisible()
  await page.goBack()
  await expect(hostLocation(page)).toHaveText(detail)
  await expect(
    page.getByLabel("Redirect URIs, one per line", { exact: true })
  ).toHaveValue("https://shop.example/callback\nhttps://shop.example/other")

  await page.getByRole("button", { name: "Delete" }).click()
  await page
    .getByRole("alertdialog")
    .getByLabel("Type Shop to confirm.")
    .fill("Shop")
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Delete" })
    .click()
  await expect(hostLocation(page)).toHaveText(base)
  await expect(page.getByText("No clients yet.")).toBeVisible()
  await page.context().close()
})

test("OAuthClientsAdmin alone: a deep link, read-only and no-access states", async ({
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
  const base = `/alone/oauth-clients/${group}`
  const maker = await signedInAt(browser, owner, `${base}/new`)
  await maker.getByLabel("Type").selectOption("none")
  await maker.getByLabel("Name").fill("Mobile")
  await maker
    .getByLabel("Redirect URIs, one per line", { exact: true })
    .fill("https://app.example/cb")
  await maker.getByRole("button", { name: "Register client" }).click()
  await expect(maker.getByRole("region", { name: "Mobile" })).toBeVisible()
  await expect(maker).toHaveURL(new RegExp(`${base}/goc_[^/]+$`))
  await expect(maker.getByLabel(/^Client secret of/)).toHaveCount(0)
  const detail = new URL(maker.url()).pathname
  await maker.context().close()

  const reader = await signedInAt(browser, viewer, detail)
  await expect(reader.getByLabel("Name")).toHaveValue("Mobile")
  await expect(reader.getByLabel("Name")).toBeDisabled()
  await expect(reader.getByRole("button", { name: "Save" })).toHaveCount(0)
  await expect(reader.getByRole("button", { name: "Delete" })).toHaveCount(0)
  await reader.getByRole("link", { name: "Back" }).click()
  await expect(
    reader
      .getByRole("table", { name: "OAuth clients" })
      .getByRole("link", { name: "Mobile", exact: true })
  ).toBeVisible()
  await expect(reader.getByRole("link", { name: "New client" })).toHaveCount(0)
  await reader.context().close()

  const outsider = await signedInAt(browser, staff, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await outsider.context().close()
})
