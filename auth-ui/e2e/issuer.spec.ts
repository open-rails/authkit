import path from "node:path"

import { expect, test, type BrowserContext, type Page } from "@playwright/test"

import { registerVerified } from "./support/api"

// The console (127.0.0.1) calls the issuer (localhost): Chrome's Local
// Network Access asks for permission between the two loopback names.
test.use({ permissions: ["local-network-access"] })

const dist = path.resolve(import.meta.dirname, "../dist")
const authorizeApp = path.resolve(
  import.meta.dirname,
  ".react-app/authorize.js"
)

// The console (fixtures/console.js, on 127.0.0.1) runs createIssuerClient
// against the e2e server (localhost) as its issuer, whose authorize page is
// the packaged OAuthAuthorize (fixtures/authorize.html).
async function serve(context: BrowserContext) {
  await context.route("**/__auth-ui/**/*.js", (route, req) => {
    const file = new URL(req.url()).pathname.replace(/^\/__auth-ui\//, "")
    return route.fulfill({
      path: file === "authorize.js" ? authorizeApp : path.join(dist, file),
      contentType: "text/javascript",
    })
  })
}

type Win = {
  issuer: import("../src/client/index.ts").IssuerClient
  callback: unknown
  booted?: boolean
  popupResult?: Promise<string>
}

const win = (page: Page) => page as Page
const booted = (page: Page) =>
  expect
    .poll(() =>
      win(page)
        .evaluate(() => !!(window as unknown as Win).booted)
        .catch(() => false)
    )
    .toBe(true)
const callback = (page: Page) =>
  page.evaluate(() => (window as unknown as Win).callback).catch(() => null)
const snapshot = (page: Page) =>
  page.evaluate(() => (window as unknown as Win).issuer.getSnapshot())
const storedSession = (page: Page) =>
  page.evaluate(
    () =>
      new Promise<unknown>((resolve) => {
        const req = indexedDB.open("authkit")
        req.onsuccess = () => {
          const db = req.result
          if (!db.objectStoreNames.contains("issuer-sessions"))
            return resolve(null)
          const get = db
            .transaction("issuer-sessions")
            .objectStore("issuer-sessions")
            .getAll()
          get.onsuccess = () => resolve(get.result[0] ?? null)
        }
      })
  )

test("issuer client: code flow with DPoP across origins, reload, popup, sign-out", async ({
  page,
  context,
  request,
  baseURL,
}) => {
  const issuer = baseURL!
  const origin = issuer.replace("://localhost:", "://127.0.0.1:")
  await serve(context)
  const authorizes: string[] = []
  context.on("request", (r) => {
    if (new URL(r.url()).pathname === "/oauth2/authorize")
      authorizes.push(r.url())
  })

  // Signed in at the issuer.
  await page.goto("/")
  const { email, password } = await registerVerified(page, request)

  // The console signs in there by redirect and comes back with its tokens.
  await page.goto(`${origin}/console.html`)
  await booted(page)
  expect(await snapshot(page)).toMatchObject({ status: "anonymous" })
  await page.evaluate(() => {
    void (window as unknown as Win).issuer.signIn({ returnTo: "/after" })
  })
  await expect
    .poll(() => callback(page), { timeout: 15_000 })
    .toEqual({ kind: "signed_in", returnTo: "/after" })
  const signedIn = await snapshot(page)
  expect(signedIn).toMatchObject({
    status: "authenticated",
    claims: { client_id: "e2e-console", aud: `${issuer}/__test/resource` },
  })
  expect(new URL(page.url()).search).toBe("")
  const jkt = (signedIn as { claims: { cnf: { jkt: string } } }).claims.cnf.jkt
  const authorize = new URL(authorizes[0])
  expect(authorize.searchParams.get("dpop_jkt")).toBe(jkt)
  expect(authorize.searchParams.get("code_challenge_method")).toBe("S256")
  expect(authorize.searchParams.get("resource")).toBe(
    `${issuer}/__test/resource`
  )

  // Cross-origin API call: DPoP proof, the server's nonce, CORS.
  const api = await page.evaluate(async (url) => {
    const { issuer } = window as unknown as Win
    const res = await issuer.authFetch(url)
    return {
      status: res.status,
      body: await res.json(),
      user: issuer.getUser(),
    }
  }, `${issuer}/__test/resource/whoami`)
  expect(api).toMatchObject({
    status: 200,
    body: {
      sub: (signedIn as { userId: string }).userId,
      client_id: "e2e-console",
      jkt,
    },
    user: { email },
  })

  // A step-up (max_age=0) re-authenticates at the issuer: its authorize page
  // asks for the password, then the console gets fresher tokens.
  await page.waitForTimeout(1100)
  await page.evaluate(() => {
    void (window as unknown as Win).issuer.stepUp({ returnTo: "/stepped-up" })
  })
  const stepUp = page.getByRole("dialog", { name: "Confirm it's you" })
  await stepUp.waitFor()
  await stepUp.getByLabel("Password", { exact: true }).fill(password)
  await stepUp.getByRole("button", { name: "Confirm" }).click()
  await expect
    .poll(() => callback(page), { timeout: 15_000 })
    .toEqual({ kind: "signed_in", returnTo: "/stepped-up" })
  expect(new URL(authorizes[1]).searchParams.get("max_age")).toBe("0")
  const authTime = (s: unknown) =>
    (s as { claims: { auth_time: number } }).claims.auth_time
  expect(authTime(await snapshot(page))).toBeGreaterThan(authTime(signedIn))

  // The refresh token is kept in IndexedDB, never localStorage, and a reload
  // restores the session from it without another authorization request.
  const stored = (await storedSession(page)) as { refreshToken?: string }
  expect(stored?.refreshToken).toBeTruthy()
  expect(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage })
    )
  ).not.toContain(stored.refreshToken!)
  await page.reload()
  await booted(page)
  expect(await snapshot(page)).toMatchObject({
    status: "authenticated",
    userId: (signedIn as { userId: string }).userId,
  })
  expect(authorizes).toHaveLength(2)
  expect(
    ((await storedSession(page)) as { refreshToken: string }).refreshToken
  ).not.toBe(stored.refreshToken)

  // Signed out here only; the popup signs in again at the issuer.
  await page.evaluate(() =>
    (window as unknown as Win).issuer.signOut({ redirect: false })
  )
  expect(await snapshot(page)).toMatchObject({ status: "anonymous" })
  expect(await storedSession(page)).toBeNull()
  const popup = page.waitForEvent("popup")
  await page.click("#popup")
  await (await popup).waitForEvent("close")
  expect(
    await page.evaluate(() => (window as unknown as Win).popupResult)
  ).toBe("ok")
  expect(await snapshot(page)).toMatchObject({ status: "authenticated" })

  // Sign-out ends the issuer session and returns to the console.
  await page.evaluate(() => {
    void (window as unknown as Win).issuer.signOut()
  })
  await page.waitForURL(`${origin}/signed-out.html`)
  await booted(page)
  expect(await snapshot(page)).toMatchObject({ status: "anonymous" })
  expect(await storedSession(page)).toBeNull()

  // With nobody signed in, prompt=none comes back login_required.
  await page.evaluate(() => {
    void (window as unknown as Win).issuer.signIn({ prompt: "none" })
  })
  await expect
    .poll(() => callback(page), { timeout: 15_000 })
    .toEqual({ error: "login_required" })
})
