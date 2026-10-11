import { generateKeyPairSync } from "node:crypto"

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

const publicPEM = () =>
  generateKeyPairSync("rsa", { modulusLength: 2048 })
    .publicKey.export({ type: "spki", format: "pem" })
    .toString()

test("RemoteApplicationsAdmin in a host router: register by JWKS and by PEM with a step-up, disable, delete", async ({
  browser,
  request,
}) => {
  test.setTimeout(120_000)
  const owner = await newUser(browser, request)
  const group = await merchantGroup(request, owner.email)
  const base = `/router/remote-applications/${group}`
  const page = await signedInAt(browser, owner, base)
  await expect(page.getByText("No signing keys yet.")).toBeVisible()
  const sign = page.getByRole("region", { name: "Sign this" })
  const origin = new URL(page.url()).origin
  await expect(sign).toContainText(`"aud": "${origin}/oauth2/token"`)

  await page.getByLabel("Issuer").fill("https://shop.example")
  await expect(sign).toContainText(`"iss": "https://shop.example"`)
  await page
    .getByLabel("JWKS URL", { exact: true })
    .fill("https://shop.example/.well-known/jwks.json")
  await page.getByRole("button", { name: "Register key" }).click()
  await expect(
    page.getByText("https://shop.example was registered.")
  ).toBeVisible()
  const table = page.getByRole("table", { name: "Registered keys" })
  await expect(table.getByRole("row", { name: /shop\.example/ })).toContainText(
    "Enabled"
  )
  await expect(hostLocation(page)).toHaveText(base)

  // The same issuer again is refused.
  await page.getByLabel("Issuer").fill("https://shop.example")
  await page
    .getByLabel("JWKS URL", { exact: true })
    .fill("https://shop.example/keys")
  await page.getByRole("button", { name: "Register key" }).click()
  await expect(
    page.getByText("That issuer already belongs to another remote application.")
  ).toBeVisible()

  // Registering keys needs a recent sign-in.
  await staleSessions(request, owner.email)
  await page.reload()
  await page.getByLabel("Issuer").fill("https://backend.example")
  await page.getByLabel("Key", { exact: true }).selectOption("pem")
  await page.getByLabel("Key ID").fill("k1")
  await page.getByLabel("Public key (PEM)", { exact: true }).fill(publicPEM())
  await page.getByRole("button", { name: "Register key" }).click()
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await stepUp.getByLabel("Password").fill(owner.password)
  await stepUp.getByRole("button", { name: "Confirm" }).click()
  await expect(
    page.getByText("https://backend.example was registered.")
  ).toBeVisible()
  await expect(
    table.getByRole("row", { name: /backend\.example/ })
  ).toContainText("k1")

  await page
    .getByRole("button", { name: "Disable: https://backend.example" })
    .click()
  await expect(
    page.getByText("https://backend.example was disabled.")
  ).toBeVisible()
  await expect(
    table.getByRole("row", { name: /backend\.example/ })
  ).toContainText("Disabled")
  const listed = await groupAPI(
    page,
    "GET",
    `/groups/${group}/remote-applications`
  )
  expect(
    (listed.body!.data as { issuer: string; enabled: boolean }[])
      .map((a) => [a.issuer, a.enabled])
      .sort()
  ).toEqual([
    ["https://backend.example", false],
    ["https://shop.example", true],
  ])

  await page
    .getByRole("button", { name: "Delete: https://shop.example" })
    .click()
  await page
    .getByRole("alertdialog")
    .getByRole("button", { name: "Delete" })
    .click()
  await expect(
    page.getByText("https://shop.example was deleted.")
  ).toBeVisible()
  await expect(table.getByRole("row")).toHaveCount(2)
  await page.context().close()
})

test("RemoteApplicationsAdmin alone: read-only and no-access states", async ({
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
  const base = `/alone/remote-applications/${group}`
  const maker = await signedInAt(browser, owner, base)
  await maker.getByLabel("Issuer").fill("https://shop.example")
  await maker
    .getByLabel("JWKS URL", { exact: true })
    .fill("https://shop.example/jwks.json")
  await maker.getByRole("button", { name: "Register key" }).click()
  await expect(
    maker.getByText("https://shop.example was registered.")
  ).toBeVisible()
  await maker.context().close()

  const reader = await signedInAt(browser, viewer, base)
  await expect(
    reader.getByRole("table", { name: "Registered keys" })
  ).toContainText("https://shop.example")
  await expect(
    reader.getByRole("button", { name: "Register key" })
  ).toHaveCount(0)
  await expect(
    reader.getByRole("button", { name: /^(Disable|Delete):/ })
  ).toHaveCount(0)
  await expect(reader.getByRole("region", { name: "Sign this" })).toContainText(
    `"iss": "https://shop.example"`
  )
  await reader.context().close()

  const outsider = await signedInAt(browser, staff, base)
  await expect(
    outsider.getByRole("region", { name: "No access" })
  ).toBeVisible()
  await outsider.context().close()
})
