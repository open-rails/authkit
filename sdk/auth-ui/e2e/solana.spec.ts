import { generateKeyPairSync, sign, type KeyObject } from "node:crypto"
import path from "node:path"

import { expect, test, type Page } from "@playwright/test"

import type { AuthClient } from "../src/client/index.ts"
import type { SolanaAuth } from "../src/solana/index.ts"
import { registerVerified, totp } from "./support/api"

type Win = {
  auth: AuthClient
  solana: SolanaAuth
  walletSign(address: string, message: string): Promise<string>
}
type Result = { ok: true; value: unknown } | { ok: false; code: string }

const app = path.resolve(import.meta.dirname, ".react-app/solana.js")
const signInApp = path.resolve(import.meta.dirname, ".react-app/sign-in.js")

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
function base58(bytes: Uint8Array): string {
  let n = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`)
  let out = ""
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out
    n /= 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    out = `1${out}`
  }
  return out
}

// An in-test Ed25519 wallet; the browser signer calls back into it.
function newWallet() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url")
  return { address: base58(raw), key: privateKey }
}
type Wallet = ReturnType<typeof newWallet>
const wallets = new Map<string, KeyObject>()
const wallet = () => {
  const w = newWallet()
  wallets.set(w.address, w.key)
  return w
}

// The in-page signer calls back into the test's Ed25519 keys.
function exposeWallet(page: Page) {
  return page.exposeFunction(
    "walletSign",
    (address: string, message: string): string => {
      const key = wallets.get(address)
      if (!key) throw new Error(`unknown wallet ${address}`)
      return sign(null, Buffer.from(message, "base64"), key).toString("base64")
    }
  )
}

// The packaged entries, bundled with their real dependencies.
async function loadSolana(page: Page) {
  await page.route("**/__auth-ui/solana-app.js", (route) =>
    route.fulfill({ path: app, contentType: "text/javascript" })
  )
  await exposeWallet(page)
  await page.goto("/")
  await page.addScriptTag({ url: "/__auth-ui/solana-app.js", type: "module" })
  await page.waitForFunction(() => "solana" in window)
}

// Runs one SolanaAuth call with an in-page signer for `address`.
function call(
  page: Page,
  op: "signIn" | "link" | "unlink",
  address = "",
  opts: { tamper?: boolean; password?: string } = {}
): Promise<Result> {
  return page.evaluate(
    async ({ op, address, opts }) => {
      const w = window as unknown as Win
      const toB64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
      const fromB64 = (s: string) =>
        Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
      const signer = {
        publicKey: address,
        signMessage: async (m: Uint8Array) => {
          const sig = fromB64(await w.walletSign(address, toB64(m)))
          if (opts.tamper) sig[0] ^= 0xff
          return sig
        },
      }
      try {
        const value =
          op === "signIn"
            ? await w.solana.signIn(signer)
            : op === "link"
              ? await w.solana.link(signer)
              : await w.solana.unlink({ password: opts.password })
        return { ok: true as const, value }
      } catch (err) {
        const e = err as { code?: string; reason?: string; name?: string }
        return {
          ok: false as const,
          code: e.code ?? e.reason ?? e.name ?? "?",
        }
      }
    },
    { op, address, opts }
  )
}

const userId = (page: Page) =>
  page.evaluate(() => {
    const s = (window as unknown as Win).auth.getSnapshot()
    return s.status === "authenticated" ? s.userId : null
  })
const signOut = (page: Page) =>
  page.evaluate(() => (window as unknown as Win).auth.signOut())

test("wallet sign-in creates and restores the wallet account", async ({
  page,
}) => {
  await loadSolana(page)
  const a: Wallet = wallet()

  expect(await call(page, "signIn", a.address)).toEqual({
    ok: true,
    value: { kind: "session" },
  })
  const first = await userId(page)
  expect(first).toBeTruthy()
  const me = await page.evaluate(() => (window as unknown as Win).auth.getMe())
  expect(me).toMatchObject({ id: first, solana_address: a.address })

  // The wallet is the only login method.
  expect(await call(page, "unlink")).toEqual({
    ok: false,
    code: "cannot_unlink_last_login_method",
  })

  await signOut(page)
  expect(await call(page, "signIn", a.address)).toMatchObject({ ok: true })
  expect(await userId(page)).toBe(first)

  await signOut(page)
  expect(await call(page, "signIn", a.address, { tamper: true })).toEqual({
    ok: false,
    code: "invalid_signature",
  })
  expect(await userId(page)).toBeNull()
})

test("link, conflict, unlink and relink a wallet", async ({
  page,
  request,
}) => {
  await loadSolana(page)
  const taken = wallet()
  expect(await call(page, "signIn", taken.address)).toMatchObject({ ok: true })
  await signOut(page)

  const { email, password } = await registerVerified(page, request)
  expect(
    await page.evaluate(
      (input) => (window as unknown as Win).auth.signInWithPassword(input),
      { identifier: email, password }
    )
  ).toEqual({ kind: "session" })
  const owner = await userId(page)

  const b = wallet()
  expect(await call(page, "link", b.address)).toEqual({
    ok: true,
    value: { address: b.address },
  })
  expect(await call(page, "link", taken.address)).toEqual({
    ok: false,
    code: "wallet_already_linked",
  })
  const c = wallet()
  expect(await call(page, "link", c.address)).toEqual({
    ok: false,
    code: "wallet_change_requires_unlink",
  })

  expect(await call(page, "unlink", "", { password })).toEqual({
    ok: true,
    value: undefined,
  })
  expect(await call(page, "link", c.address)).toMatchObject({ ok: true })

  // The linked wallet now signs in to the email account.
  await signOut(page)
  expect(await call(page, "signIn", c.address)).toMatchObject({ ok: true })
  expect(await userId(page)).toBe(owner)
})

test("SignInDialog: wallet sign-in continues to the TOTP prompt", async ({
  page,
}) => {
  await page.route("**/__auth-ui/sign-in.js", (route) =>
    route.fulfill({ path: signInApp, contentType: "text/javascript" })
  )
  await exposeWallet(page)
  await page.goto("/")
  await page.addScriptTag({ url: "/__auth-ui/sign-in.js", type: "module" })
  const status = page.getByTestId("status")
  await expect(status).toHaveText("anonymous")
  const a = wallet()
  await page.evaluate((address) => {
    Object.assign(window, { walletAddress: address })
  }, a.address)

  const dialog = page.getByRole("dialog")
  const walletSignIn = async () => {
    await page.getByRole("button", { name: "open sign in" }).click()
    await dialog.getByRole("button", { name: "Continue with Solana" }).click()
  }
  type Client = {
    enableTwoFactor(input: { method: string; code?: string }): Promise<{
      secret?: string
    }>
    getSnapshot(): { status: string; userId?: string }
  }
  const owned = () =>
    page.evaluate(
      () =>
        (window as unknown as { authClient: Client }).authClient.getSnapshot()
          .userId
    )
  const enroll = (code?: string) =>
    page.evaluate(
      async (code) =>
        (
          await (
            window as unknown as { authClient: Client }
          ).authClient.enableTwoFactor({ method: "totp", code })
        ).secret ?? "",
      code
    )

  // First wallet sign-in creates the account.
  await walletSignIn()
  await expect(dialog).toBeHidden()
  await expect(status).toHaveText("authenticated")
  const owner = await owned()

  // Enroll TOTP early in a step so the login code can use the next one.
  const into = Date.now() % 30_000
  if (into > 20_000) await page.waitForTimeout(30_500 - into)
  const now = Date.now()
  const secret = await enroll()
  await enroll(totp(secret, now))
  await page.getByRole("button", { name: "sign out" }).click()
  await expect(status).toHaveText("anonymous")

  // Wallet sign-in → AuthKit 2fa_required → the dialog's TOTP prompt.
  await walletSignIn()
  await expect(
    dialog.getByRole("heading", { name: "Verify it's you" })
  ).toBeVisible()
  await expect(status).toHaveText("anonymous")
  await dialog
    .getByRole("textbox", { name: "Verification code" })
    .fill(totp(secret, now + 30_000))
  await expect(dialog).toBeHidden()
  await expect(status).toHaveText("authenticated")
  expect(await owned()).toBe(owner)
})
