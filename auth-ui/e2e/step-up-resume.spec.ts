import { expect as baseExpect, test, type Page } from "@playwright/test"

import {
  groupAPI,
  linkIdP,
  merchantGroup,
  openAdmin,
  routeAdminApp,
  signInAtIdP,
  staleSessions,
} from "./support/admin"
import { registerVerified } from "./support/api"

const expect = baseExpect.configure({ timeout: 15_000 })
const PENDING = "authkit:step-up:pending"
const PARAM = "authkit_step_up"

const stored = (page: Page) =>
  page.evaluate((key) => sessionStorage.getItem(key), PENDING)

test("a provider step-up replays the guarded write once; a stale, foreign or mismatched one is dropped", async ({
  page,
  request,
}) => {
  test.setTimeout(240_000)
  await routeAdminApp(page)
  await page.goto("/")
  const { email } = await registerVerified(page, request)
  const group = await merchantGroup(request, email)
  const subject = `idp-${Date.now()}`
  const url = `/stepup/oauth/${group}`
  await openAdmin(page, url)
  await expect(page.getByTestId("status")).toHaveText("authenticated")
  await linkIdP(page, subject)

  const clients = async () => {
    await openAdmin(page, url)
    const res = await groupAPI(page, "GET", `/groups/${group}/oauth-clients`)
    expect(res.status).toBe(200)
    return (res.body!.data as { client_name: string }[])
      .map((c) => c.client_name)
      .sort()
  }
  // A stale sign-in, then the write: the dialog sends the browser to the
  // IdP, the action kept for the return.
  const toIdP = async (name: string) => {
    await staleSessions(request, email)
    await openAdmin(page, url)
    await page.getByLabel("client name").fill(name)
    await page.getByRole("button", { name: "create client" }).click()
    await page.getByRole("button", { name: /Use GitHub/i }).click()
    await expect(page.getByLabel("Subject")).toBeVisible()
    expect(await stored(page)).toContain(name)
  }

  const returned = page.waitForRequest((r) => r.url().includes(`${PARAM}=`))
  await toIdP("resumed-once")
  await signInAtIdP(page, subject)
  await expect(page.getByTestId("log")).toHaveText("resumed:resumed-once")
  const returnURL = (await returned).url()
  expect(new URL(page.url()).searchParams.has(PARAM)).toBe(false)
  expect(await stored(page)).toBeNull()
  // The return URL again, without a fresh step-up, replays nothing.
  await openAdmin(page, returnURL)
  await expect(page.getByTestId("log")).toBeEmpty()
  expect(await clients()).toEqual(["resumed-once"])

  for (const [label, patch] of [
    ["stale", { createdAt: Date.now() - 16 * 60_000 }],
    ["foreign", { actor: "00000000-0000-7000-8000-000000000000" }],
    ["mismatched", { nonce: "not-the-returned-nonce" }],
  ] as const) {
    await toIdP(`dropped-${label}`)
    await page.evaluate(
      ([key, change]) => {
        const record = JSON.parse(sessionStorage.getItem(key)!)
        sessionStorage.setItem(key, JSON.stringify({ ...record, ...change }))
      },
      [PENDING, patch] as const
    )
    await signInAtIdP(page, subject)
    await expect(page.getByTestId("status")).toHaveText("authenticated")
    await expect.poll(() => stored(page)).toBeNull()
    expect(new URL(page.url()).searchParams.has(PARAM)).toBe(false)
    // The step-up itself held: the next write needs none.
    await page.getByLabel("client name").fill(`after-${label}`)
    await page.getByRole("button", { name: "create client" }).click()
    await expect(page.getByTestId("log")).toHaveText(`created:after-${label}`)
  }
  expect(await clients()).toEqual([
    "after-foreign",
    "after-mismatched",
    "after-stale",
    "resumed-once",
  ])
})
