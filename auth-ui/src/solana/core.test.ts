import { describe, expect, it, vi } from "vitest"

import { createAuthClient } from "../client/client.ts"
import { AuthKitError, AuthSessionChangedError } from "../client/errors.ts"
import {
  authResult,
  complete,
  deferred,
  json,
  jwt,
  stubFetch,
  tokens,
  authError,
} from "../client/testing.ts"
import {
  createSolanaAuth,
  fromBase58,
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
        return json(200, complete("U", undefined, { created: true }))
      },
    })
    const sign = vi.fn<(m: Uint8Array) => Promise<Uint8Array>>(async () => SIG)
    await expect(
      solana.signIn(signer(sign), { username: "neo" })
    ).resolves.toMatchObject({ status: "complete", created: true })

    const bytes = new TextEncoder().encode(MESSAGE)
    expect(sign).toHaveBeenCalledWith(bytes)
    const [challenge] = challengeFn.mock.lastCall!
    expect(bodyOf(challenge)).toEqual({ address: "W", username: "neo" })
    expect(header(challenge, "Authorization")).toBeUndefined()
    expect(header(login, "Authorization")).toBeUndefined()
    expect(bodyOf(login)).toEqual({
      output: {
        account: { address: "W", publicKey: b64(Uint8Array.of(29)) },
        signature: b64(SIG),
        signedMessage: b64(bytes),
      },
    })
    expect(client.getSnapshot()).toMatchObject({
      status: "authenticated",
      userId: "U",
    })
  })

  it("returns a second-factor step like password login", async () => {
    const totp = {
      id: "f",
      method: "totp",
      is_default: true,
      destination: null,
    }
    const { client, solana } = setup({
      "POST /api/v1/solana/login": [
        json(
          200,
          authResult("second_factor_required", {
            second_factor: {
              user_id: "U",
              challenge: "c",
              factor: totp,
              factors: [totp],
            },
          })
        ),
      ],
    })
    await expect(solana.signIn(signer())).resolves.toMatchObject({
      status: "second_factor_required",
      second_factor: { user_id: "U", challenge: "c" },
    })
    expect(client.getSnapshot().status).not.toBe("authenticated")
  })

  it.each(["logout", "replacement"])(
    "discards a wallet login that lands after %s",
    async (change) => {
      const signed = deferred<Uint8Array>()
      const fetch = stubFetch({
        "POST /api/v1/solana/challenge": challengeRoute(),
        "POST /api/v1/solana/login": () => tokens("A"),
        "DELETE /api/v1/logout": () => new Response(null, { status: 204 }),
      })
      const client = createAuthClient({ fetch })
      await client.completeSignIn(async () => complete("X"))
      const sign = vi.fn(() => signed.promise)
      const pending = createSolanaAuth(client).signIn(signer(sign))
      await vi.waitFor(() => expect(sign).toHaveBeenCalled())
      if (change === "logout") await client.signOut()
      else await client.completeSignIn(async () => complete("B"))
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
      "POST /api/v1/solana/login": () => tokens("U"),
    })
    const first = solana.signIn(signer(vi.fn(() => signed.promise)))
    await expect(solana.signIn(signer())).rejects.toMatchObject({
      reason: "busy",
    })
    signed.resolve(SIG)
    await expect(first).resolves.toMatchObject({ status: "complete" })
    await expect(solana.signIn(signer())).resolves.toMatchObject({
      status: "complete",
    })
  })
})

describe("link", () => {
  const signedIn = async (routes: Parameters<typeof stubFetch>[0]) => {
    const s = setup(routes)
    await s.client.completeSignIn(async () => complete("A"))
    return s
  }

  it("links with the session bearer", async () => {
    let link!: RequestInit
    const { solana } = await signedIn({
      "PUT /api/v1/me/solana-wallet": (init) => {
        link = init
        return json(200, { provider: "solana", address: "W", verified: true })
      },
    })
    await expect(solana.link(signer())).resolves.toEqual({ address: "W" })
    expect(header(link, "Authorization")).toBe(`Bearer ${jwt("A")}`)
    expect(bodyOf(link).output.account).toEqual({
      address: "W",
      publicKey: b64(Uint8Array.of(29)),
    })
  })

  it("requires a session and refuses a wallet change before signing", async () => {
    const anon = setup({})
    await expect(anon.solana.link(signer())).rejects.toMatchObject({
      code: "unauthenticated",
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
    const linkRoute = vi.fn(() =>
      json(200, { provider: "solana", address: "W", verified: true })
    )
    const { client, solana } = await signedIn({
      "PUT /api/v1/me/solana-wallet": linkRoute,
    })
    const sign = vi.fn(() => signed.promise)
    const pending = solana.link(signer(sign))
    await vi.waitFor(() => expect(sign).toHaveBeenCalled())
    await client.completeSignIn(async () => complete("B"))
    signed.resolve(SIG)
    await expect(pending).rejects.toBeInstanceOf(AuthSessionChangedError)
    expect(linkRoute).not.toHaveBeenCalled()
  })

  it("surfaces AuthKit link conflicts", async () => {
    const { solana } = await signedIn({
      "PUT /api/v1/me/solana-wallet": [authError(409, "wallet_already_linked")],
    })
    await expect(solana.link(signer())).rejects.toMatchObject({
      status: 409,
      code: "wallet_already_linked",
    })
  })
})

it("unlink deletes the solana provider, without a body", async () => {
  let del!: RequestInit
  const { solana } = setup({
    "DELETE /api/v1/me/providers/solana": (init) => {
      del = init
      return new Response(null, { status: 204 })
    },
  })
  await solana.unlink()
  expect(del.body).toBeUndefined()
})

describe("stepUp", () => {
  it("signs the session's step-up challenge and adopts the fresh session", async () => {
    let stepUp!: RequestInit
    const fresh = {
      last_authenticated_at: null,
      step_up_required_for_sensitive_actions: false,
      step_up_required_in_seconds: 900,
      auth_methods: ["swk"],
    }
    const { client, fetch, solana } = setup({
      "POST /api/v1/me/step-up/solana/challenge": () =>
        json(200, { nonce: "n", message: MESSAGE, issued_at: "t" }),
      "POST /api/v1/me/step-up/solana": (init) => {
        stepUp = init
        return json(200, complete("A", undefined, { fresh_auth: fresh }))
      },
    })
    await client.completeSignIn(async () => complete("A"))
    const sign = vi.fn(async () => SIG)
    await expect(solana.stepUp(signer(sign))).resolves.toEqual(fresh)
    expect(sign).toHaveBeenCalledWith(new TextEncoder().encode(MESSAGE))
    expect(header(stepUp, "Authorization")).toBe(`Bearer ${jwt("A")}`)
    expect(bodyOf(stepUp)).toEqual({
      output: {
        account: { address: "W", publicKey: b64(Uint8Array.of(29)) },
        signature: b64(SIG),
        signedMessage: b64(new TextEncoder().encode(MESSAGE)),
      },
    })
    expect(
      fetch.mock.calls.some(([url]) =>
        String(url).endsWith("/api/v1/solana/challenge")
      )
    ).toBe(false)
  })
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

describe("fromBase58", () => {
  it("decodes addresses to their 32 key bytes", () => {
    expect(fromBase58("11111111111111111111111111111111")).toEqual(
      new Uint8Array(32)
    )
    const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1)
    expect(fromBase58("4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw")).toEqual(
      key
    )
    expect(fromBase58("0OIl")).toBeNull()
  })
})
