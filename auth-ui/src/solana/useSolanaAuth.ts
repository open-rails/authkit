import { useCallback, useEffect, useMemo, useRef, useState } from "react"

import type { AuthClient, AuthOutcome } from "../client/client.ts"
import {
  createSolanaAuth,
  isSolanaWalletError,
  signerFromWallet,
  type SolanaSigner,
  type WalletAdapterLike,
} from "./core.ts"

type Action = "signIn" | "link"

export type UseSolanaAuthOptions = {
  // Open the host's wallet picker (e.g. wallet-adapter-react-ui setVisible(true)).
  // The requested action resumes once the wallet connects.
  onConnectRequest?: () => void
  // For hosts that load their wallet stack on demand: resolves a connected
  // signer per action, used instead of `wallet`. Rejecting with
  // SolanaWalletError("rejected") (picker dismissed) ends the action quietly.
  acquireSigner?: () => Promise<SolanaSigner>
  onSignIn?: (outcome: AuthOutcome) => void
  onLink?: (address: string) => void
  // Refuses a different wallet before prompting for a signature.
  linkedAddress?: string | null
  // Username for an account created by wallet sign-in.
  username?: string
}

export type SolanaAuthState = {
  busy: Action | "unlink" | null
  awaitingWallet: Action | null
  error: unknown
}

// Pass wallet-adapter's useWallet() (or any WalletAdapterLike) as `wallet`,
// or null with `options.acquireSigner`.
export function useSolanaAuth(
  client: AuthClient,
  wallet: WalletAdapterLike | null | undefined,
  options: UseSolanaAuthOptions = {}
) {
  const solana = useMemo(() => createSolanaAuth(client), [client])
  const [state, setState] = useState<SolanaAuthState>({
    busy: null,
    awaitingWallet: null,
    error: null,
  })
  const latest = useRef({ wallet, options })
  useEffect(() => {
    latest.current = { wallet, options }
  })
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const update = useCallback((next: Partial<SolanaAuthState>) => {
    if (mounted.current) setState((s) => ({ ...s, ...next }))
  }, [])

  const run = useCallback(
    async <T>(
      action: Action,
      perform: (signer: SolanaSigner, opts: UseSolanaAuthOptions) => Promise<T>
    ): Promise<T | null> => {
      const { wallet: w, options: opts } = latest.current
      let signer: SolanaSigner
      if (opts.acquireSigner) {
        update({ busy: action, awaitingWallet: null, error: null })
        try {
          signer = await opts.acquireSigner()
        } catch (err) {
          const dismissed =
            isSolanaWalletError(err) && err.reason === "rejected"
          update({ busy: null, error: dismissed ? null : err })
          return null
        }
      } else {
        try {
          signer = signerFromWallet(w)
        } catch (err) {
          if (
            isSolanaWalletError(err) &&
            err.reason === "not_connected" &&
            opts.onConnectRequest
          ) {
            update({ awaitingWallet: action, error: null })
            opts.onConnectRequest()
            return null
          }
          update({ error: err })
          return null
        }
        update({ busy: action, awaitingWallet: null, error: null })
      }
      try {
        const out = await perform(signer, opts)
        update({ busy: null })
        return out
      } catch (err) {
        update({ busy: null, error: err })
        return null
      }
    },
    [update]
  )

  const signIn = useCallback(
    () =>
      run("signIn", async (signer, opts) => {
        const outcome = await solana.signIn(signer, { username: opts.username })
        opts.onSignIn?.(outcome)
        return outcome
      }),
    [run, solana]
  )

  const link = useCallback(
    () =>
      run("link", async (signer, opts) => {
        const { address } = await solana.link(signer, {
          linkedAddress: opts.linkedAddress,
        })
        opts.onLink?.(address)
        return address
      }),
    [run, solana]
  )

  const unlink = useCallback(
    async (input: { password?: string } = {}) => {
      update({ busy: "unlink", error: null })
      try {
        await solana.unlink(input)
        update({ busy: null })
        return true
      } catch (err) {
        update({ busy: null, error: err })
        return false
      }
    },
    [solana, update]
  )

  const cancel = useCallback(() => update({ awaitingWallet: null }), [update])

  // Resume the action that asked for a wallet once one connects.
  const ready = !!(wallet?.connected && wallet.publicKey)
  const { awaitingWallet } = state
  useEffect(() => {
    if (!ready || !awaitingWallet) return
    void (awaitingWallet === "signIn" ? signIn() : link())
  }, [ready, awaitingWallet, signIn, link])

  return {
    ...state,
    signIn,
    link,
    unlink,
    cancel,
    connected: ready,
    connecting: !!wallet?.connecting,
    address: ready ? (wallet?.publicKey?.toBase58() ?? null) : null,
  }
}
