import { createHmac, randomUUID } from "node:crypto"
import {
  expect,
  test as base,
  type APIRequestContext,
  type Page,
} from "@playwright/test"
import type { AuthClient } from "@openrails/auth-ui/client"
import type { AdminClient } from "@openrails/auth-ui/admin"

declare global {
  interface Window {
    __criticalMethod?: (method: string) => Promise<void>
    ak: {
      client: AuthClient
      admin: AdminClient
      refresh?: Promise<boolean>
      transportFailure: typeof import("@openrails/auth-ui/client").transportFailure
      readAuthKitError: typeof import("@openrails/auth-ui/client").readAuthKitError
      events: {
        kind: string
        userId?: string
        status?: string
        hasAccessToken?: boolean
        profileUserId?: string
        email?: string
      }[]
    }
  }
}
export const test = base.extend({
  page: async ({ page }, runTest, info) => {
    const observed = new Set<string>()
    await page.exposeFunction("__criticalMethod", (method: string) => {
      observed.add(method)
    })
    await runTest(page)
    await info.attach("public-client-invocations", {
      body: JSON.stringify({ methods: [...observed].sort() }),
      contentType: "application/json",
    })
  },
})

export const password = "Critical-browser-password-9"
export const identity = () => {
  const username = `crit${randomUUID().replaceAll("-", "").slice(0, 16)}`
  return { username, email: `${username}@example.test`, password }
}
export async function open(page: Page, query = "") {
  await page.goto(`/${query}`)
  await expect(page.getByTestId("session-status")).toHaveText("anonymous")
}
export async function seed(
  request: APIRequestContext,
  options: Record<string, unknown> = {}
) {
  const who = identity()
  const response = await request.post("/__fixture/user", {
    data: { ...who, verified: true, ...options },
  })
  expect(response.status(), await response.text()).toBe(201)
  const user = (await response.json()) as { id: string }
  return { ...who, ...user }
}
export async function login(
  page: Page,
  who: { email: string; password: string }
) {
  return page.evaluate(
    (who) =>
      window.ak.client.signInWithPassword({
        identifier: who.email,
        password: who.password,
      }),
    who
  )
}
export async function deliveries(request: APIRequestContext, to: string) {
  const response = await request.get(
    `/__fixture/deliveries?to=${encodeURIComponent(to)}`
  )
  expect(response.status()).toBe(200)
  return (await response.json()) as {
    kind: string
    code?: string
    token?: string
    link?: string
  }[]
}
export async function code(
  request: APIRequestContext,
  to: string,
  kind = "verification"
) {
  let result: string | undefined
  await expect
    .poll(async () => {
      result = (await deliveries(request, to)).findLast(
        (message) => message.kind === kind
      )?.code
      return result
    })
    .toBeTruthy()
  return result!
}
export async function register(page: Page, request: APIRequestContext) {
  const who = identity()
  const pending = await page.evaluate(
    (who) =>
      window.ak.client.register({
        identifier: who.email,
        username: who.username,
        password: who.password,
      }),
    who
  )
  expect(pending).toBeNull()
  const proof = await code(request, who.email)
  const result = await page.evaluate(
    ({ who, proof }) =>
      window.ak.client.confirmVerification({
        identifier: who.email,
        code: proof,
      }),
    { who, proof }
  )
  expect(result?.status).toBe("complete")
  await expect(page.getByTestId("session-status")).toHaveText("authenticated")
  const id = await page.evaluate(() => {
    const s = window.ak.client.getSnapshot()
    return s.status === "authenticated" ? s.userId : null
  })
  expect(id).toBeTruthy()
  return { ...who, id: id! }
}

export async function nextCode(
  request: APIRequestContext,
  to: string,
  after: number
) {
  let result: string | undefined
  await expect
    .poll(async () => {
      result = (await deliveries(request, to))
        .slice(after)
        .findLast((message) => !!message.code)?.code
      return result
    })
    .toBeTruthy()
  return result!
}

// Independent RFC6238 authenticator input; the real AuthKit verifier checks it.
export function totp(secret: string, at = Date.now()) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const bytes: number[] = []
  let word = 0
  let bits = 0
  for (const symbol of secret.replace(/=+$/, "").toUpperCase()) {
    const n = alphabet.indexOf(symbol)
    if (n < 0) throw new Error("invalid authenticator setup key")
    word = (word << 5) | n
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((word >>> bits) & 255)
      word &= (1 << bits) - 1
    }
  }
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)))
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest()
  return String(
    (digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1_000_000
  ).padStart(6, "0")
}
export async function enrollRequired(
  page: Page,
  enrollment: import("@openrails/auth-ui/client").TokenSet
) {
  const setup = await page.evaluate(
    (enrollment) =>
      window.ak.client.setupTwoFactor(
        { method: "totp" },
        { enrollmentToken: enrollment }
      ),
    enrollment
  )
  expect(setup.secret).toBeTruthy()
  const created = await page.evaluate(
    ({ enrollment, code }) =>
      window.ak.client.addTwoFactorFactor(
        { method: "totp", code },
        { enrollmentToken: enrollment }
      ),
    { enrollment, code: totp(setup.secret!) }
  )
  expect(created.auth?.status).toBe("complete")
  return created
}
