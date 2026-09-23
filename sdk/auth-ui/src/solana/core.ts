import type { AuthClient, AuthOutcome } from "../client/client.ts"
import { AuthKitError, AuthSessionChangedError } from "../client/errors.ts"

// Any wallet reduces to this: wallet-adapter, wallet-standard, Phantom, a test key.
export type SolanaSigner = {
  // base58 address
  publicKey: string
  signMessage(message: Uint8Array): Promise<Uint8Array>
}

// Structural subset of wallet-adapter's useWallet(); no runtime import.
export type WalletAdapterLike = {
  publicKey: { toBase58(): string } | null
  signMessage?: (message: Uint8Array) => Promise<Uint8Array>
  connected: boolean
  connecting?: boolean
}

export type SolanaWalletErrorReason =
  "not_connected" | "unsupported" | "rejected" | "invalid_signature" | "busy"

// A wallet-side failure; AuthKit rejections surface as AuthKitError.
export class SolanaWalletError extends Error {
  readonly reason: SolanaWalletErrorReason
  constructor(reason: SolanaWalletErrorReason, options?: ErrorOptions) {
    super(`Solana wallet: ${reason}`, options)
    this.name = "SolanaWalletError"
    this.reason = reason
  }
}

export const isSolanaWalletError = (
  value: unknown
): value is SolanaWalletError => value instanceof SolanaWalletError

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Public key bytes of a base58 address; null for a malformed one.
export function fromBase58(text: string): Uint8Array | null {
  let value = 0n
  for (const ch of text) {
    const digit = BASE58.indexOf(ch)
    if (digit < 0) return null
    value = value * 58n + BigInt(digit)
  }
  const bytes: number[] = []
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn))
    value >>= 8n
  }
  for (const ch of text) {
    if (ch !== "1") break
    bytes.unshift(0)
  }
  return Uint8Array.from(bytes)
}

// Standard base64: AuthKit decodes StdEncoding first.
export function toBase64(bytes: Uint8Array): string {
  let bin = ""
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

// Throws not_connected / unsupported so callers can prompt for a wallet.
export function signerFromWallet(
  wallet: WalletAdapterLike | null | undefined
): SolanaSigner {
  const key = wallet?.connected ? wallet.publicKey : null
  if (!wallet || !key) throw new SolanaWalletError("not_connected")
  const sign = wallet.signMessage
  if (!sign) throw new SolanaWalletError("unsupported")
  return { publicKey: key.toBase58(), signMessage: (m) => sign(m) }
}

type Rec = Record<string, unknown>

const publicKeyOf = (address: string) => {
  const key = fromBase58(address)
  return key ? { address, publicKey: toBase64(key) } : { address }
}

export type SolanaAuth = ReturnType<typeof createSolanaAuth>

export function createSolanaAuth(client: AuthClient) {
  let inFlight = false

  const exclusive = async <T>(run: () => Promise<T>): Promise<T> => {
    if (inFlight) throw new SolanaWalletError("busy")
    inFlight = true
    try {
      return await run()
    } finally {
      inFlight = false
    }
  }

  const challenge = async (
    address: string,
    username: string | undefined,
    anonymous: boolean
  ): Promise<string> => {
    const body = await client.request<Rec>("POST", "/solana/challenge", {
      body: { address, username },
      ...(anonymous ? { bearer: null } : {}),
    })
    const message = body?.message
    if (typeof message !== "string" || !message)
      throw new Error("AuthKit returned no SIWS message")
    return message
  }

  // challenge → wallet signature → SIWS output body
  const prove = async (
    signer: SolanaSigner,
    username: string | undefined,
    anonymous: boolean
  ) => {
    const address = signer.publicKey
    if (!address) throw new SolanaWalletError("not_connected")
    const message = await challenge(address, username, anonymous)
    const bytes = new TextEncoder().encode(message)
    let signature: Uint8Array
    try {
      signature = await signer.signMessage(bytes)
    } catch (cause) {
      throw new SolanaWalletError("rejected", { cause })
    }
    if (!(signature instanceof Uint8Array) || signature.length !== 64)
      throw new SolanaWalletError("invalid_signature")
    return {
      address,
      body: {
        output: {
          // SIWS output shape: the key travels beside its address.
          account: publicKeyOf(address),
          signature: toBase64(signature),
          signedMessage: toBase64(bytes),
        },
      },
    }
  }

  const userId = () => {
    const s = client.getSnapshot()
    return s.status === "authenticated" ? s.userId : null
  }

  return {
    // Signs in or creates the wallet's account. Continuations (2FA, recovery…)
    // are returned like password login; a session change mid-signature throws.
    signIn: (
      signer: SolanaSigner,
      input: { username?: string } = {}
    ): Promise<AuthOutcome> =>
      exclusive(() =>
        client.completeSignIn(async () => {
          const { body } = await prove(signer, input.username, true)
          return client.request("POST", "/solana/login", {
            body,
            bearer: null,
          })
        })
      ),

    // Links the wallet to the signed-in account. Pass the currently linked
    // address to refuse a wallet change before prompting for a signature.
    link: (
      signer: SolanaSigner,
      input: { linkedAddress?: string | null } = {}
    ): Promise<{ address: string }> =>
      exclusive(async () => {
        const owner = userId()
        if (!owner)
          throw new AuthKitError(401, {
            type: "",
            code: "authentication_required",
            message: "Sign in before linking a wallet.",
          })
        if (input.linkedAddress && input.linkedAddress !== signer.publicKey)
          throw new AuthKitError(409, {
            type: "",
            code: "wallet_change_requires_unlink",
            message: "Unlink your current wallet before connecting another.",
          })
        const { address, body } = await prove(signer, undefined, false)
        if (userId() !== owner) throw new AuthSessionChangedError()
        const out = await client.request<Rec>("POST", "/solana/link", {
          body,
        })
        const linked = out?.solana_address
        return { address: typeof linked === "string" ? linked : address }
      }),

    unlink: (input: { password?: string } = {}) =>
      client.unlinkProvider("solana", input),
  }
}
