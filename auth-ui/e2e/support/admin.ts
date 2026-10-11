import path from "node:path"

import { expect, type APIRequestContext, type Page } from "@playwright/test"

import { api } from "./api"

const app = path.resolve(import.meta.dirname, "../.react-app/admin.js")

// The e2e server answers /<mode>/<view>/<group>/… with fixtures/admin.html,
// which loads this bundle.
export async function routeAdminApp(page: Page) {
  await page.route("**/__auth-ui/admin.js", (r) =>
    r.fulfill({ path: app, contentType: "text/javascript" })
  )
}

export async function openAdmin(page: Page, url: string) {
  await page.goto(url)
  await expect(page.getByTestId("status")).not.toHaveText("loading")
}

// A merchant group with the user of email holding role there.
export async function merchantGroup(
  request: APIRequestContext,
  email: string,
  role = "owner"
): Promise<string> {
  const res = await request.post(
    `/__test/groups?email=${encodeURIComponent(email)}&role=${role}`
  )
  expect(res.ok(), await res.text()).toBe(true)
  return ((await res.json()) as { id: string }).id
}

// Ages the user's sessions so the next refreshed token needs a step-up.
export async function staleSessions(request: APIRequestContext, email: string) {
  const res = await request.post(
    `/__test/stale-sessions?email=${encodeURIComponent(email)}`
  )
  expect(res.status()).toBe(204)
}

// Links the test IdP's subject to the signed-in account, through the real
// provider redirect; ends back on the app origin.
export async function linkIdP(page: Page, subject: string) {
  const url = await page.evaluate(() =>
    (
      window as unknown as {
        authClient: { startProviderLink(p: string): Promise<string> }
      }
    ).authClient.startProviderLink("github")
  )
  await page.goto(url)
  await signInAtIdP(page, subject)
  await expect(page).toHaveURL(/result=success/)
}

export async function signInAtIdP(page: Page, subject: string) {
  await page.getByLabel("Subject").fill(subject)
  await page.getByRole("button", { name: "Continue" }).click()
}

// The access token of the page's session.
export async function accessTokenOf(page: Page): Promise<string> {
  return page.evaluate(() =>
    (
      window as unknown as { authClient: { getAccessToken(): string } }
    ).authClient.getAccessToken()
  )
}

export async function groupAPI(
  page: Page,
  method: string,
  path: string,
  body?: unknown
) {
  return api(page, method, path, body, await accessTokenOf(page))
}
