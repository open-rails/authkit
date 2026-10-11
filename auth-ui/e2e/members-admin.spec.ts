import { expect as baseExpect, test } from "@playwright/test"

import {
  addMember,
  groupAPI,
  hostLocation,
  merchantGroup,
  newUser,
  signedInAt,
} from "./support/admin"

const expect = baseExpect.configure({ timeout: 15_000 })

const username = (email: string) =>
  `u${email.slice("e2e-".length, email.indexOf("@"))}`

test("MembersAdmin in a host router: roles, the role filter in the URL, invitations, removal", async ({
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
  const base = `/router/members/${group}`
  const page = await signedInAt(browser, owner, base)
  const table = page.getByRole("table", { name: "Members" })
  await expect(table.getByRole("row")).toHaveCount(4)
  // The last owner can be neither demoted nor removed.
  await expect(
    page.getByLabel(`Role of ${username(owner.email)}`)
  ).toBeDisabled()

  await page
    .getByLabel(`Role of ${username(staff.email)}`)
    .selectOption("merchant:viewer")
  await expect(
    page.getByText(`${username(staff.email)} now holds Viewer.`)
  ).toBeVisible()

  // The filter lives in the host router's URL; back undoes it.
  await page.getByLabel("Role", { exact: true }).selectOption("merchant:viewer")
  await expect(hostLocation(page)).toHaveText(`${base}?role=merchant%3Aviewer`)
  await expect(table.getByRole("row")).toHaveCount(3)
  await page.goBack()
  await expect(hostLocation(page)).toHaveText(base)
  await expect(table.getByRole("row")).toHaveCount(4)

  // A host link switches the view; the component's tab switches it back.
  await page.getByRole("link", { name: "host: invitations" }).click()
  await expect(
    page.getByRole("region", { name: "Invitations", exact: true })
  ).toBeVisible()
  await page.getByRole("button", { name: "Invite" }).click()
  const link = page.getByLabel("Invitation link")
  await expect(link).toHaveValue(/invite|code|http/)
  await page.getByLabel("Email").fill("someone@example.test")
  await page.getByRole("button", { name: "Invite" }).click()
  await expect(
    page.getByText("An invitation went to someone@example.test.")
  ).toBeVisible()
  const sent = page.getByRole("table", { name: "Sent invitations" })
  await expect(sent.getByRole("row")).toHaveCount(3)
  await sent.getByRole("button", { name: "Revoke" }).first().click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Revoke" })
    .click()
  await expect(page.getByText("The invitation was revoked.")).toBeVisible()
  await expect(sent.getByText("Revoked")).toHaveCount(1)
  await page.getByRole("link", { name: "Members", exact: true }).click()
  await expect(hostLocation(page)).toHaveText(base)

  await page
    .getByRole("button", { name: `Remove: ${username(viewer.email)}` })
    .click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Remove" })
    .click()
  await expect(
    page.getByText(`${username(viewer.email)} was removed.`)
  ).toBeVisible()
  await expect(table.getByRole("row")).toHaveCount(3)
  await page.context().close()
})

test("MembersAdmin alone: read without write controls, no access, an outranked change refused", async ({
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
  const base = `/alone/members/${group}`

  const reader = await signedInAt(browser, viewer, base)
  await expect(
    reader.getByRole("table", { name: "Members" }).getByRole("row")
  ).toHaveCount(5)
  await expect(reader.getByRole("combobox", { name: /^Role of/ })).toHaveCount(
    0
  )
  await expect(reader.getByRole("button", { name: /^Remove/ })).toHaveCount(0)
  // Deep link, history default: the invitations view without the form.
  await reader.goto(`${base}/invitations`)
  await expect(
    reader.getByRole("region", { name: "Sent invitations" })
  ).toBeVisible()
  await expect(reader.getByRole("button", { name: "Invite" })).toHaveCount(0)
  await reader.getByRole("link", { name: "Members", exact: true }).click()
  await expect(reader).toHaveURL(new RegExp(`${base}$`))
  await reader.context().close()

  const outsider = await signedInAt(browser, staff, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await expect(outsider.getByRole("table")).toHaveCount(0)
  await outsider.context().close()

  // An admin holds less than the owner role: giving it, or changing the
  // owner's, is refused by AuthKit.
  const manager = await signedInAt(browser, admin, base)
  await manager
    .getByLabel(`Role of ${username(staff.email)}`)
    .selectOption("merchant:owner")
  await expect(
    manager.getByText("That role confers authority you do not hold.")
  ).toBeVisible()
  const members = await groupAPI(
    manager,
    "GET",
    `/groups/${group}/members?kind=user&role=merchant:owner`
  )
  expect((members.body!.data as unknown[]).length).toBe(1)
  await manager.context().close()
})

test("MembersAdmin inherits the host's theme, light and dark, and fits a phone", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const owner = await newUser(browser, request)
  const group = await merchantGroup(request, owner.email)
  for (const theme of ["light", "dark"]) {
    const page = await signedInAt(
      browser,
      owner,
      `/alone/members/${group}?theme=${theme}`
    )
    await page.setViewportSize({ width: 390, height: 844 })
    await expect(page.getByRole("table", { name: "Members" })).toBeVisible()
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
    expect(look.overflow).toBeLessThanOrEqual(0)
    await page.context().close()
  }
})
