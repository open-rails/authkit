import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../client/client.ts"
import { AuthKitError, AuthSessionChangedError } from "../client/errors.ts"
import { authError, deferred, json, jwt, stubFetch } from "../client/testing.ts"
import {
  createSolanaAuth,
  signerFromWallet,
  SolanaWalletError,
} from "./core.ts"

const MESSAGE = "localhost wants you to sign in with your Solana account:\nW é"
const SIG = new Uint8Array(64).fill(7)
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64")

const signer = (
  sign: (m: Uint8Array) => Promise<Uint8Array> = vi.fn(async () => SIG)
) => ({
  publicKey: "W",
  signMessage: sign,
})

const challengeRoute = () =>
  vi.fn((init: RequestInit & { url: string }) => {
    void init
    return json(200, { nonce: "n", message: MESSAGE, issued_at: "t" })
  })

const setup = (routes: Parameters<typeof stubFetch>[0]) => {
  const challenge = challengeRoute()
  const fetch = stubFetch({
    "POST /api/v1/solana/challenge": challenge,
    ...routes,
  })
  const client = createAuthClient({ fetch })
  return { fetch, client, challenge, solana: createSolanaAuth(client) }
}

const bodyOf = (init: RequestInit) => JSON.parse(String(init.body))
const header = (init: RequestInit, name: string) =>
  (init.headers as Record<string, string>)[name]

describe("signIn", () => {
  it("signs the UTF-8 challenge and posts base64 SIWS output anonymously", async () => {
    let login!: RequestInit
    const {
      client,
      challenge: challengeFn,
      solana,
    } = setup({
      "POST /api/v1/solana/login": (init) => {
        login = init
        return json(200, {
          token_set: { access_token: jwt("U"), expires_in: 900 },
          created: true,
        })
      },
    })
    const sign = vi.fn<(m: Uint8Array) => Promise<Uint8Array>>(async () => SIG)
    await expect(
      solana.signIn(signer(sign), { username: "neo" })
    ).resolves.toEqual({
      kind: "session",
    })

    const bytes = new TextEncoder().encode(MESSAGE)
    expect(sign).toHaveBeenCalledWith(bytes)
    const [challenge] = challengeFn.mock.lastCall!
    expect(bodyOf(challenge)).toEqual({ address: "W", username: "neo" })
    expect(header(challenge, "Authorization")).toBeUndefined()
    expect(header(login, "Authorization")).toBeUndefined()
    expect(bodyOf(login)).toEqual({
      output: {
        account: { address: "W" },
        signature: b64(SIG),
        signedMessage: b64(bytes),
      },
    })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "U",
    })
  })

  it("returns a 2FA continuation like password login", async () => {
    const { client, solana } = setup({
      "POST /api/v1/solana/login": [
        authError(403, "2fa_required", {
          user_id: "U",
          challenge: "c",
          method: "totp",
        }),
      ],
    })
    await expect(solana.signIn(signer())).resolves.toMatchObject({
      kind: "2fa_required",
      userId: "U",
      challenge: "c",
    })
    expect(client.getSnapshot().status).not.toBe("authenticated")
  })

  it.each(["logout", "replacement"])(
    "discards a wallet login that lands after %s",
    async (change) => {
      const signed = deferred<Uint8Array>()
      const fetch = stubFetch({
        "POST /api/v1/solana/challenge": challengeRoute(),
        "POST /api/v1/solana/login": () =>
          json(200, { token_set: { access_token: jwt("A") } }),
        "DELETE /api/v1/logout": () => new Response(null, { status: 204 }),
      })
      const client = createAuthClient({ fetch })
      await client.completeSignIn(async () => ({ access_token: jwt("X") }))
      const sign = vi.fn(() => signed.promise)
      const pending = createSolanaAuth(client).signIn(signer(sign))
      await vi.waitFor(() => expect(sign).toHaveBeenCalled())
      if (change === "logout") await client.signOut()
      else await client.completeSignIn(async () => ({ access_token: jwt("B") }))
      signed.resolve(SIG)
      await expect(pending).rejects.toBeInstanceOf(AuthSessionChangedError)
      expect(client.getAccessToken()).toBe(
        change === "logout" ? null : jwt("B")
      )
    }
  )

  it("maps a wallet refusal without calling login", async () => {
    const { fetch, solana } = setup({})
    const refusal = new Error("User rejected the request.")
    const err = await solana
      .signIn(signer(vi.fn().mockRejectedValue(refusal)))
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(SolanaWalletError)
    expect(err).toMatchObject({ reason: "rejected", cause: refusal })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it("rejects a malformed signature before login", async () => {
    const { fetch, solana } = setup({})
    await expect(
      solana.signIn(signer(vi.fn(async () => new Uint8Array(12))))
    ).rejects.toMatchObject({ reason: "invalid_signature" })
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it("refuses a concurrent ceremony", async () => {
    const signed = deferred<Uint8Array>()
    const { solana } = setup({
      "POST /api/v1/solana/login": () =>
        json(200, { token_set: { access_token: jwt("U") } }),
    })
    const first = solana.signIn(signer(vi.fn(() => signed.promise)))
    await expect(solana.signIn(signer())).rejects.toMatchObject({
      reason: "busy",
    })
    signed.resolve(SIG)
    await expect(first).resolves.toEqual({ kind: "session" })
    await expect(solana.signIn(signer())).resolves.toEqual({ kind: "session" })
  })
})

describe("link", () => {
  const signedIn = async (routes: Parameters<typeof stubFetch>[0]) => {
    const s = setup(routes)
    await s.client.completeSignIn(async () => ({ access_token: jwt("A") }))
    return s
  }

  it("links with the session bearer", async () => {
    let link!: RequestInit
    const { solana } = await signedIn({
      "POST /api/v1/solana/link": (init) => {
        link = init
        return json(200, { solana_address: "W" })
      },
    })
    await expect(solana.link(signer())).resolves.toEqual({ address: "W" })
    expect(header(link, "Authorization")).toBe(`Bearer ${jwt("A")}`)
    expect(bodyOf(link).output.account).toEqual({ address: "W" })
  })

  it("requires a session and refuses a wallet change before signing", async () => {
    const anon = setup({})
    await expect(anon.solana.link(signer())).rejects.toMatchObject({
      code: "authentication_required",
    })
    const { fetch, solana } = await signedIn({})
    const sign = vi.fn(async () => SIG)
    const err = await solana
      .link(signer(sign), { linkedAddress: "OTHER" })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(AuthKitError)
    expect(err).toMatchObject({ code: "wallet_change_requires_unlink" })
    expect(sign).not.toHaveBeenCalled()
    expect(fetch).not.toHaveBeenCalled()
  })

  it("never links to an account that signed in during the signature", async () => {
    const signed = deferred<Uint8Array>()
    const linkRoute = vi.fn(() => json(200, { solana_address: "W" }))
    const { client, solana } = await signedIn({
      "POST /api/v1/solana/link": linkRoute,
    })
    const sign = vi.fn(() => signed.promise)
    const pending = solana.link(signer(sign))
    await vi.waitFor(() => expect(sign).toHaveBeenCalled())
    await client.completeSignIn(async () => ({ access_token: jwt("B") }))
    signed.resolve(SIG)
    await expect(pending).rejects.toBeInstanceOf(AuthSessionChangedError)
    expect(linkRoute).not.toHaveBeenCalled()
  })

  it("surfaces AuthKit link conflicts", async () => {
    const { solana } = await signedIn({
      "POST /api/v1/solana/link": [authError(409, "wallet_already_linked")],
    })
    await expect(solana.link(signer())).rejects.toMatchObject({
      status: 409,
      code: "wallet_already_linked",
    })
  })
})

it("unlink deletes the solana provider", async () => {
  let del!: RequestInit
  const { solana } = setup({
    "DELETE /api/v1/user/providers/solana": (init) => {
      del = init
      return new Response(null, { status: 204 })
    },
  })
  await solana.unlink({ password: "pw" })
  expect(bodyOf(del)).toEqual({ password: "pw" })
})

describe("signerFromWallet", () => {
  const key = { toBase58: () => "W" }
  it("adapts a connected wallet", async () => {
    const signMessage = vi.fn(async () => SIG)
    const s = signerFromWallet({ connected: true, publicKey: key, signMessage })
    expect(s.publicKey).toBe("W")
    await expect(s.signMessage(new Uint8Array([1]))).resolves.toBe(SIG)
  })
  it.each([
    [null, "not_connected"],
    [{ connected: false, publicKey: key }, "not_connected"],
    [{ connected: true, publicKey: null }, "not_connected"],
    [{ connected: true, publicKey: key }, "unsupported"],
  ])("rejects %j as %s", (wallet, reason) => {
    expect(() => signerFromWallet(wallet)).toThrow(
      expect.objectContaining({ reason })
    )
  })
})
