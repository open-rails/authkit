import { expect } from "@playwright/test"
import { test, seed, open, login } from "./browser"

test("AK-UI-17: AK-J29-C08: account inbox receipts and withdrawals stay with the current identity", async ({
  page,
  request,
}) => {
  const alice = await seed(request)
  const bob = await seed(request)
  const notification = { UserID: alice.id, ID: "reply:browser", Revision: 1 }
  const published = await request.post("/__fixture/notification", {
    data: notification,
  })
  expect(published.status(), await published.text()).toBe(204)
  await open(page, "?notifications")
  await login(page, alice)
  await expect(page.getByTestId("notification-count")).toHaveText("1")
  const listed = await page.evaluate(() =>
    window.ak.client.notifications.list({
      unread: true,
      signal: new AbortController().signal,
    })
  )
  expect(listed.items).toHaveLength(1)
  const id = listed.items[0].id
  const changed = await page.evaluate(async (id) => {
    let updates = 0
    const unsubscribe = window.ak.client.notifications.subscribe(
      () => updates++
    )
    const read = await window.ak.client.notifications.setRead(id)
    const unread = await window.ak.client.notifications.list({ unread: true })
    const archived = await window.ak.client.notifications.setDismissed(id)
    const active = await window.ak.client.notifications.list()
    const archive = await window.ak.client.notifications.list({
      dismissed: true,
    })
    const reopened = await window.ak.client.notifications.setDismissed(
      id,
      false
    )
    const reset = await window.ak.client.notifications.setRead(id, false)
    const fetched = await window.ak.client.notifications.get(id)
    window.ak.client.notifications.refresh()
    unsubscribe()
    return {
      read,
      unread,
      archived,
      active,
      archive,
      reopened,
      reset,
      fetched,
      updates,
    }
  }, id)
  expect(changed.read.read_at).not.toBeNull()
  expect(changed.unread.items).toHaveLength(0)
  expect(changed.archived.dismissed_at).not.toBeNull()
  expect(changed.active.items).toHaveLength(0)
  expect(changed.archive.items[0].id).toBe(id)
  expect(changed.reopened.dismissed_at).toBeNull()
  expect(changed.reset.read_at).toBeNull()
  expect(changed.fetched.id).toBe(id)
  expect(changed.updates).toBe(5)
  const withdrawn = await request.post("/__fixture/notification", {
    data: { ...notification, Revision: 2, Withdrawn: true },
  })
  expect(withdrawn.status(), await withdrawn.text()).toBe(204)
  await page.evaluate(() => window.ak.client.notifications.refresh())
  await expect(page.getByTestId("notification-count")).toHaveText("0")
  const late = await request.post("/__fixture/notification", {
    data: notification,
  })
  expect(late.status(), await late.text()).toBe(204)
  expect(
    (await page.evaluate(() => window.ak.client.notifications.list())).items
  ).toHaveLength(0)
  await page.evaluate(() => window.ak.client.signOut())
  await login(page, bob)
  await expect(page.getByTestId("notification-count")).toHaveText("0")
  expect(
    (await page.evaluate(() => window.ak.client.notifications.list())).items
  ).toHaveLength(0)
})

test("AK-UI-18: AK-J29-C09: native inbox widgets paginate, share unread state and hide withdrawn notices", async ({
  page,
  request,
}) => {
  const alice = await seed(request),
    bob = await seed(request)
  const notices = ["widget:first", "widget:second", "widget:third"]
  const publish = async (id: string, Revision: number, Withdrawn = false) => {
    const response = await request.post("/__fixture/notification", {
      data: { UserID: alice.id, ID: id, Revision, Withdrawn },
    })
    expect(response.status(), await response.text()).toBe(204)
  }
  for (const id of notices) await publish(id, 1)
  await open(page, "?notification-widgets")
  await expect(page.locator('[data-authui="notification-bell"]')).toHaveCount(0)
  const inbox = page.getByTestId("notification-inbox")
  await expect(inbox).toContainText("Sign in to see your notifications.")
  await login(page, alice)
  const rows = inbox.locator('[data-authui="notification-item"]')
  await expect(rows).toHaveCount(1)
  await inbox.getByRole("button", { name: "Show more", exact: true }).click()
  await expect(rows).toHaveCount(2)
  await inbox.getByRole("button", { name: "Show more", exact: true }).click()
  await expect(rows).toHaveCount(3)
  await expect(
    inbox.getByRole("button", { name: "Show more", exact: true })
  ).toHaveCount(0)
  const bell = page.getByRole("button", {
    name: "Notifications, unread items",
    exact: true,
  })
  await bell.click()
  const popup = page.getByRole("dialog", { name: "Notifications", exact: true })
  await expect(popup.locator('[data-authui="notification-item"]')).toHaveCount(
    3
  )
  await page.keyboard.press("Escape")
  await expect(popup).toHaveCount(0)
  await expect(bell).toBeFocused()
  for (const id of notices) {
    const row = rows.filter({ hasText: id })
    await row.getByRole("button", { name: "Mark read", exact: true }).click()
    await expect(row).toHaveAttribute("data-unread", "false")
  }
  await expect(bell).toHaveCount(0)
  const first = rows.filter({ hasText: notices[0] })
  await first.getByRole("button", { name: "Dismiss", exact: true }).click()
  await expect(rows).toHaveCount(2)
  await page.reload()
  await inbox.getByRole("button", { name: "Archived", exact: true }).click()
  await expect(rows).toHaveCount(1)
  await expect(rows).toHaveAttribute("data-unread", "false")
  await rows
    .getByRole("button", { name: "Restore to inbox", exact: true })
    .click()
  await inbox.getByRole("button", { name: "All", exact: true }).click()
  await expect(rows).toHaveCount(1)
  await inbox.getByRole("button", { name: "Show more", exact: true }).click()
  await expect(rows).toHaveCount(2)
  await inbox.getByRole("button", { name: "Show more", exact: true }).click()
  await expect(rows).toHaveCount(3)
  await first.getByRole("button", { name: "Mark unread", exact: true }).click()
  await expect(bell).toBeVisible()
  await publish(notices[0], 2, true)
  await publish(notices[0], 1)
  await inbox
    .getByRole("button", { name: "Refresh notifications", exact: true })
    .click()
  await expect(rows).toHaveCount(2)
  await expect(first).toHaveCount(0)
  await expect(bell).toHaveCount(0)
  await publish(notices[0], 3)
  await inbox
    .getByRole("button", { name: "Refresh notifications", exact: true })
    .click()
  await expect(rows).toHaveCount(3)
  await expect(first).toHaveAttribute("data-unread", "true")
  await expect(bell).toBeVisible()
  await page.evaluate(() => window.ak.client.signOut())
  await expect(rows).toHaveCount(0)
  await expect(page.locator('[data-authui="notification-bell"]')).toHaveCount(0)
  await login(page, bob)
  await expect(
    inbox.getByRole("status").filter({ hasText: /^No notifications yet\.$/ })
  ).toBeVisible()
  await expect(rows).toHaveCount(0)
  await expect(bell).toHaveCount(0)
  await page.evaluate(() => window.ak.client.signOut())
  await open(page, "?notification-widgets&notification-default")
  await login(page, alice)
  await expect(inbox.getByText("You have a new notification", { exact: true })).toHaveCount(1)
})
