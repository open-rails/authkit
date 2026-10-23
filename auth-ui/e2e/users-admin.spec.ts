import { expect as baseExpect, test, type Page } from "@playwright/test"

import {
  addMember,
  grantEntitlement,
  groupAPI,
  hostLocation,
  newUser,
  openAdmin,
  rootOwnerAt,
  signedInAt,
} from "./support/admin"

const expect = baseExpect.configure({ timeout: 15_000 })

const username = (email: string) =>
  `u${email.slice("e2e-".length, email.indexOf("@"))}`

type Entry = {
  id: string
  root_role: string | null
  ban: { until: string | null; reason: string | null } | null
}

// The account as AuthKit has it, read with the page's own token.
async function entry(page: Page, name: string): Promise<Entry> {
  const res = await groupAPI(
    page,
    "GET",
    `/admin/users?search=${name}&status=any`
  )
  expect(res.status, JSON.stringify(res.body)).toBe(200)
  return (res.body!.data as Entry[])[0]
}

test("UsersAdmin in a host router: search and filters in the URL, a ban with an end and the host's warning, unban, the root role", async ({
  browser,
  request,
}) => {
  test.setTimeout(150_000)
  const target = await newUser(browser, request)
  await grantEntitlement(request, target.email, "premium")
  const name = username(target.email)
  const base = "/router/users/root"
  const page = await rootOwnerAt(browser, request, base)
  const table = page.getByRole("table", { name: "Users" })
  await expect(table).toBeVisible()

  // The search lands in the host router's URL once typing pauses; filters
  // add to it and Back takes them off.
  await page.getByLabel("Search").fill(name)
  await expect(hostLocation(page)).toHaveText(`${base}?q=${name}`)
  await expect(table.getByRole("row")).toHaveCount(2)
  await expect(page.getByText("Page 1 · Accounts: 1")).toBeVisible()
  await page.getByLabel("Entitlement").selectOption("premium")
  await expect(hostLocation(page)).toHaveText(
    `${base}?q=${name}&entitlement=premium`
  )
  await expect(table.getByRole("row")).toHaveCount(2)
  await page.getByLabel("Status").selectOption("banned")
  await expect(hostLocation(page)).toHaveText(
    `${base}?q=${name}&entitlement=premium&status=banned`
  )
  await expect(
    page.getByText("No account matches. Try another search or filter.")
  ).toBeVisible()
  await page.goBack()
  await expect(hostLocation(page)).toHaveText(
    `${base}?q=${name}&entitlement=premium`
  )
  await table.getByRole("link", { name }).click()
  await expect(hostLocation(page)).toHaveText(
    new RegExp(`^${base}/[0-9a-f-]{36}$`)
  )

  // A ban with a reason and an end, after the host's warning.
  const header = page.getByRole("region", { name })
  await expect(header.getByText("premium")).toBeVisible()
  await header.getByRole("button", { name: "Ban" }).click()
  const dialog = page.getByRole("dialog")
  await expect(
    dialog.getByText(`${name} has premium, which keeps running after a ban.`)
  ).toBeVisible()
  await dialog.getByLabel("Reason").fill("spam links")
  await dialog.getByLabel("Ends").selectOption("7")
  await dialog.getByRole("button", { name: "Ban" }).click()
  await expect(page.getByText(`${name} was banned.`)).toBeVisible()
  await expect(header.getByText(/^Banned until /)).toBeVisible()
  await expect(header.getByText("spam links")).toBeVisible()
  const banned = await entry(page, name)
  expect(banned.ban?.reason).toBe("spam links")
  const days = (Date.parse(banned.ban!.until!) - Date.now()) / 86_400_000
  expect(days).toBeGreaterThan(6.9)
  expect(days).toBeLessThan(7.1)

  // The banned view lists it with its reason.
  await page.getByRole("link", { name: /All users/ }).click()
  await expect(hostLocation(page)).toHaveText(base)
  await page.getByLabel("Status").selectOption("banned")
  await page.getByLabel("Search").fill(name)
  await expect(hostLocation(page)).toHaveText(`${base}?status=banned&q=${name}`)
  await expect(table.getByRole("cell", { name: "spam links" })).toBeVisible()
  await table.getByRole("link", { name }).click()
  await header.getByRole("button", { name: "Unban" }).click()
  await expect(page.getByText(`${name} was unbanned.`)).toBeVisible()
  await expect(header.getByText("Active", { exact: true })).toBeVisible()
  expect((await entry(page, name)).ban).toBeNull()

  // The root role, after typing the account's name.
  const role = page.getByRole("region", { name: "Root role" })
  await role.getByRole("combobox").selectOption("root:support")
  await role.getByRole("button", { name: "Save role" }).click()
  const confirm = page.getByRole("alertdialog")
  await expect(
    confirm.getByRole("button", { name: "Save role" })
  ).toBeDisabled()
  await confirm.getByLabel(`Type ${name} to confirm.`).fill(name)
  await confirm.getByRole("button", { name: "Save role" }).click()
  await expect(page.getByText(`${name} now holds Support.`)).toBeVisible()
  await expect(header.getByText("Support", { exact: true })).toBeVisible()
  expect((await entry(page, name)).root_role).toBe("root:support")

  // The role filter finds it.
  await page.getByRole("link", { name: /All users/ }).click()
  await expect(hostLocation(page)).toHaveText(base)
  await page.getByLabel("Root role").selectOption("root:support")
  await expect(hostLocation(page)).toHaveText(`${base}?role=root%3Asupport`)
  await expect(table.getByRole("link", { name })).toBeVisible()
  await page.context().close()
})

test("UsersAdmin alone: sign out everywhere, the history filter, a profile edit, delete and restore by typed confirmation, the host's panels", async ({
  browser,
  request,
}) => {
  test.setTimeout(150_000)
  const target = await newUser(browser, request)
  await grantEntitlement(request, target.email, "premium")
  const name = username(target.email)
  const base = "/alone/users/root"
  const page = await rootOwnerAt(browser, request, base)
  const { id } = await entry(page, name)
  await openAdmin(page, `${base}/${id}`)
  await expect(page.getByRole("region", { name: "Host panel" })).toHaveText(
    `Host panel for ${name}`
  )

  // The registration's session is live until signed out everywhere.
  const sessions = page.getByRole("region", { name: "Sessions" })
  await expect(sessions.getByRole("table")).toBeVisible()
  await sessions.getByRole("button", { name: "Sign out everywhere" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Sign out everywhere" })
    .click()
  await expect(
    page.getByText(`${name} was signed out everywhere.`)
  ).toBeVisible()
  await expect(sessions.getByText("Not signed in anywhere.")).toBeVisible()
  const history = page.getByRole("region", { name: "Sign-in history" })
  await expect(history.getByRole("cell", { name: "Signed in" })).toBeVisible()
  await history.getByLabel("Event").selectOption("account_sessions_revoked")
  await expect(page).toHaveURL(
    new RegExp(`${base}/${id}\\?kind=account_sessions_revoked$`)
  )
  await expect(
    history.getByRole("cell", { name: "Signed out everywhere" })
  ).toBeVisible()
  await expect(history.getByRole("cell", { name: "Signed in" })).toHaveCount(0)

  // A profile edit sends what changed.
  const renamed = `${name}x`
  await page.getByRole("button", { name: "Edit profile" }).click()
  const edit = page.getByRole("dialog")
  await edit.getByLabel("Username").fill(renamed)
  await edit.getByLabel("Language").fill("de")
  await edit.getByRole("button", { name: "Save" }).click()
  await expect(
    page.getByText(`The profile of ${name} was saved.`)
  ).toBeVisible()
  const details = page.getByRole("region", { name: "Details" })
  await expect(details.getByText(renamed, { exact: true })).toBeVisible()
  await expect(details.getByText("German", { exact: true })).toBeVisible()

  // Delete needs the name typed; the host's warning shows first.
  const header = page.getByRole("region", { name: renamed })
  await header.getByRole("button", { name: "Delete" }).click()
  const confirm = page.getByRole("alertdialog")
  await expect(
    confirm.getByText(
      `${renamed} has premium, which keeps running after a delete.`
    )
  ).toBeVisible()
  await expect(confirm.getByRole("button", { name: "Delete" })).toBeDisabled()
  await confirm.getByLabel(`Type ${renamed} to confirm.`).fill(name)
  await expect(confirm.getByRole("button", { name: "Delete" })).toBeDisabled()
  await confirm.getByLabel(`Type ${renamed} to confirm.`).fill(renamed)
  await confirm.getByRole("button", { name: "Delete" }).click()
  await expect(page.getByText(`${renamed} was deleted.`)).toBeVisible()
  await expect(header.getByText("Deleted", { exact: true })).toBeVisible()
  await expect(header.getByRole("button", { name: "Ban" })).toHaveCount(0)

  // The deleted view lists it; restore brings it back.
  await page.getByRole("link", { name: /All users/ }).click()
  await expect(page).toHaveURL(new RegExp(`${base}$`))
  await page.getByLabel("Status").selectOption("deleted")
  await page.getByLabel("Search").fill(renamed)
  await expect(page).toHaveURL(
    new RegExp(`${base}\\?status=deleted&q=${renamed}$`)
  )
  await page
    .getByRole("table", { name: "Users" })
    .getByRole("link", { name: renamed })
    .click()
  await header.getByRole("button", { name: "Restore" }).click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Restore" })
    .click()
  await expect(page.getByText(`${renamed} was restored.`)).toBeVisible()
  await expect(header.getByText("Active", { exact: true })).toBeVisible()
  await page.context().close()
})

test("UsersAdmin without write permissions shows no write controls, and without users:read no access", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const [support, target, nobody] = await Promise.all(
    [0, 1, 2].map(() => newUser(browser, request))
  )
  await addMember(request, "root", support.email, "support")
  const name = username(target.email)
  const base = "/alone/users/root"

  const reader = await signedInAt(browser, support, base)
  await expect(reader.getByRole("navigation")).toHaveCount(0)
  await reader.getByLabel("Search").fill(name)
  await reader
    .getByRole("table", { name: "Users" })
    .getByRole("link", { name })
    .click()
  await expect(reader.getByRole("region", { name })).toBeVisible()
  await expect(reader.getByRole("region", { name: "Sessions" })).toBeVisible()
  await expect(
    reader.getByRole("button", {
      name: /^(Ban|Unban|Delete|Restore|Edit profile|Sign out everywhere|Save role)$/,
    })
  ).toHaveCount(0)
  // Root roles need members:read on root.
  await expect(reader.getByRole("region", { name: "Root role" })).toHaveCount(0)
  await reader.context().close()

  const outsider = await signedInAt(browser, nobody, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await expect(outsider.getByRole("table")).toHaveCount(0)
  await outsider.context().close()
})

test("UserAccountSummary links to the account; UsersAdmin inherits the host's theme, light and dark, and fits a phone", async ({
  browser,
  request,
}) => {
  test.setTimeout(150_000)
  const [moderator, target] = await Promise.all(
    [0, 1].map(() => newUser(browser, request))
  )
  await addMember(request, "root", moderator.email, "moderator")
  await grantEntitlement(request, target.email, "premium")
  const name = username(target.email)
  const page = await signedInAt(browser, moderator, "/alone/users/root")
  const { id } = await entry(page, name)
  const ban = await groupAPI(page, "PUT", `/admin/users/${id}/ban`, {
    reason: "chargebacks",
  })
  expect(ban.status, JSON.stringify(ban.body)).toBe(204)

  await openAdmin(page, `/alone/user-summary/${id}`)
  const summary = page.getByRole("region", { name: "Account" })
  await expect(summary.getByText(name)).toBeVisible()
  await expect(summary.getByText("Banned permanently")).toBeVisible()
  await expect(summary.getByText("chargebacks")).toBeVisible()
  await expect(summary.getByText("premium")).toBeVisible()
  await summary.getByRole("link", { name: "Open account" }).click()
  await expect(page).toHaveURL(new RegExp(`/alone/users/root/${id}$`))
  await expect(page.getByRole("region", { name })).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  for (const theme of ["light", "dark"])
    for (const view of ["", `/${id}`]) {
      await openAdmin(page, `/alone/users/root${view}?theme=${theme}`)
      await expect(
        page.getByRole("region", { name: view ? name : "Users" })
      ).toBeVisible()
      const look = await page.evaluate(() => {
        const root = document.querySelector(".authui")!
        return {
          theme: root.getAttribute("data-authui-theme"),
          color: getComputedStyle(root).color,
          host: getComputedStyle(document.body).color,
          overflow: document.documentElement.scrollWidth - window.innerWidth,
        }
      })
      expect(look.theme).toBe("inherit")
      expect(look.color, theme).toBe(look.host)
      expect(look.overflow, `${theme} ${view}`).toBeLessThanOrEqual(0)
    }
  await page.context().close()
})
