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
