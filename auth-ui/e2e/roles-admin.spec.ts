import { expect as baseExpect, test } from "@playwright/test"

import {
  addMember,
  groupAPI,
  hostLocation,
  merchantGroup,
  newUser,
  signedInAt,
  staleSessions,
} from "./support/admin"

const expect = baseExpect.configure({ timeout: 15_000 })

test("RolesAdmin in a host router: a custom role created, edited and deleted", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const owner = await newUser(browser, request)
  const group = await merchantGroup(request, owner.email)
  const base = `/router/roles/${group}`
  const page = await signedInAt(browser, owner, base)
  const table = page.getByRole("table", { name: "Roles" })
  for (const role of ["Owner", "Staff", "Viewer", "Admin"])
    await expect(
      table.getByRole("link", { name: role, exact: true })
    ).toBeVisible()

  await page.getByRole("link", { name: "New role" }).click()
  await expect(hostLocation(page)).toHaveText(`${base}/new`)
  await page.getByLabel("Name").fill("storefront")
  await expect(page.getByText("merchant:custom-storefront")).toBeVisible()
  await page.getByRole("checkbox", { name: /Read billing/ }).check()
  await page
    .getByRole("checkbox", { name: /See the members and invitations/ })
    .check()
  await page.getByRole("button", { name: "Create role" }).click()
  await expect(hostLocation(page)).toHaveText(
    `${base}/merchant%3Acustom-storefront`
  )
  const allows = page.getByRole("list", { name: "What it allows" })
  await expect(allows.getByText("merchant:billing:read")).toBeVisible()
  await expect(allows.getByText("merchant:members:read")).toBeVisible()

  await page.getByRole("link", { name: "Edit" }).click()
  await page
    .getByRole("checkbox", { name: /See the members and invitations/ })
    .uncheck()
  await page.getByRole("button", { name: "Save role" }).click()
  const role = `${base}/merchant%3Acustom-storefront`
  await expect(hostLocation(page)).toHaveText(role)
  await expect(allows.getByText("merchant:billing:read")).toBeVisible()
  await expect(allows.getByText("merchant:members:read")).toHaveCount(0)
  // Back through the editor to the role, in the host router's history.
  await page.goBack()
  await expect(hostLocation(page)).toHaveText(`${role}/edit`)
  await page.goBack()
  await expect(hostLocation(page)).toHaveText(role)

  await page.getByRole("button", { name: "Delete" }).click()
  const confirm = page.getByRole("alertdialog")
  await expect(confirm.getByRole("button", { name: "Delete" })).toBeDisabled()
  await confirm.getByLabel("Type storefront to confirm.").fill("storefront")
  await confirm.getByRole("button", { name: "Delete" }).click()
  await expect(hostLocation(page)).toHaveText(base)
  await expect(table.getByRole("link", { name: "storefront" })).toHaveCount(0)
  await page.context().close()
})

test("RolesAdmin alone: no grant beyond the editor's own, read-only and no-access states", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const [owner, staff, viewer, admin] = await Promise.all(
    [0, 1, 2, 3].map(() => newUser(browser, request))
  )
  const group = await merchantGroup(request, owner.email)
  await addMember(request, group, staff.email, "staff")
  await addMember(request, group, viewer.email, "viewer")
  await addMember(request, group, admin.email, "admin")
  const base = `/alone/roles/${group}`

  const editor = await signedInAt(browser, admin, `${base}/new`)
  await expect(
    editor.getByRole("checkbox", { name: /Change billing/ })
  ).toBeDisabled()
  await expect(
    editor.getByRole("checkbox", { name: /Read billing/ })
  ).toBeEnabled()
  // AuthKit refuses it too.
  const refused = await groupAPI(editor, "POST", `/groups/${group}/roles`, {
    name: "refunds",
    permissions: ["merchant:billing:manage"],
  })
  expect(refused.status).toBe(403)
  await editor.context().close()

  const reader = await signedInAt(browser, viewer, base)
  await expect(reader.getByRole("table", { name: "Roles" })).toBeVisible()
  await expect(reader.getByRole("link", { name: "New role" })).toHaveCount(0)
  await reader.getByRole("link", { name: "Owner", exact: true }).click()
  await expect(
    reader.getByRole("list", { name: "What it allows" })
  ).toBeVisible()
  await expect(reader.getByRole("button", { name: "Delete" })).toHaveCount(0)
  await reader.context().close()

  const outsider = await signedInAt(browser, staff, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await outsider.context().close()
})

test("RolesAdmin on root: root staff define a root role, stepping up first", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const staffer = await newUser(browser, request)
  await addMember(request, "root", staffer.email, "rolesadmin")
  const page = await signedInAt(browser, staffer, "/alone/roles/root/new")
  // A fresh sign-in; age it so the root change asks for a step-up.
  await staleSessions(request, staffer.email)
  await page.reload()
  // The root group is the whole server's: a name of this run's own.
  const name = `auditor-${Date.now().toString(36)}`
  await page.getByLabel("Name").fill(name)
  await page.getByRole("checkbox", { name: /root:members:read/ }).check()
  await expect(
    page.getByRole("checkbox", { name: /root:roles:manage/ })
  ).toBeEnabled()
  await page.getByRole("button", { name: "Create role" }).click()
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await expect(stepUp).toBeVisible()
  await stepUp.getByLabel("Password").fill(staffer.password)
  await stepUp.getByRole("button", { name: "Confirm" }).click()
  await expect(page).toHaveURL(
    new RegExp(`/alone/roles/root/root%3Acustom-${name}$`)
  )
  await expect(
    page
      .getByRole("list", { name: "What it allows" })
      .getByText("root:members:read")
  ).toBeVisible()
  await page.context().close()
})
