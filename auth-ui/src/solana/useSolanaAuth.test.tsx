/** @vitest-environment jsdom */
import { act, renderHook, waitFor } from "@testing-library/react"
import { expect, it, vi } from "vitest"

import { createAuthClient } from "../client/client.ts"
import { json, jwt, stubFetch } from "../client/testing.ts"
import { SolanaWalletError, type WalletAdapterLike } from "./core.ts"
import { useSolanaAuth, type UseSolanaAuthOptions } from "./useSolanaAuth.ts"

const SIG = new Uint8Array(64).fill(1)
const client = () =>
  createAuthClient({
    fetch: stubFetch({
      "POST /api/v1/solana/challenge": () => json(200, { message: "m" }),
      "POST /api/v1/solana/login": () =>
        json(200, { token_set: { access_token: jwt("U") } }),
    }),
  })
const connected = (
  signMessage: (m: Uint8Array) => Promise<Uint8Array> = vi.fn(async () => SIG)
): WalletAdapterLike => ({
  connected: true,
  publicKey: { toBase58: () => "W" },
  signMessage,
})
const disconnected: WalletAdapterLike = { connected: false, publicKey: null }

it("asks for a wallet, then resumes sign-in once it connects", async () => {
  const auth = client()
  const onConnectRequest = vi.fn()
  const onSignIn = vi.fn()
  const opts: UseSolanaAuthOptions = { onConnectRequest, onSignIn }
  const { result, rerender } = renderHook(
    ({ wallet }) => useSolanaAuth(auth, wallet, opts),
    { initialProps: { wallet: disconnected } }
  )
  await act(async () => {
    expect(await result.current.signIn()).toBeNull()
  })
  expect(onConnectRequest).toHaveBeenCalledOnce()
  expect(result.current.awaitingWallet).toBe("signIn")

  rerender({ wallet: connected() })
  await waitFor(() =>
    expect(onSignIn).toHaveBeenCalledWith({ kind: "session" })
  )
  expect(result.current).toMatchObject({
    busy: null,
    awaitingWallet: null,
    error: null,
    address: "W",
  })
  expect(auth.getSnapshot()).toMatchObject({ userId: "U" })
})

it("reports a refused signature as a wallet error and returns to idle", async () => {
  const auth = client()
  const wallet = connected(vi.fn().mockRejectedValue(new Error("rejected")))
  const { result } = renderHook(() => useSolanaAuth(auth, wallet))
  await act(async () => {
    expect(await result.current.signIn()).toBeNull()
  })
  expect(result.current.busy).toBeNull()
  expect(result.current.error).toMatchObject({ reason: "rejected" })
  expect(auth.getSnapshot().status).not.toBe("authenticated")
})

it("without a connect handler, a missing wallet is an error", async () => {
  const { result } = renderHook(() => useSolanaAuth(client(), disconnected))
  await act(async () => {
    await result.current.link()
  })
  expect(result.current.error).toMatchObject({ reason: "not_connected" })
  expect(result.current.awaitingWallet).toBeNull()
})

it("acquireSigner: signs in with the acquired signer and ignores a dismissed picker", async () => {
  const auth = client()
  const onSignIn = vi.fn()
  const acquireSigner = vi
    .fn()
    .mockRejectedValueOnce(new SolanaWalletError("rejected"))
    .mockResolvedValueOnce({ publicKey: "W", signMessage: async () => SIG })
  const { result } = renderHook(() =>
    useSolanaAuth(auth, null, { acquireSigner, onSignIn })
  )
  await act(async () => {
    expect(await result.current.signIn()).toBeNull()
  })
  expect(result.current).toMatchObject({ busy: null, error: null })

  await act(async () => {
    expect(await result.current.signIn()).toEqual({ kind: "session" })
  })
  expect(onSignIn).toHaveBeenCalledWith({ kind: "session" })
  expect(auth.getSnapshot()).toMatchObject({ userId: "U" })
})

it("acquireSigner: a wallet that fails to load is an error", async () => {
  const failure = new Error("chunk failed")
  const { result } = renderHook(() =>
    useSolanaAuth(client(), null, {
      acquireSigner: () => Promise.reject(failure),
    })
  )
  await act(async () => {
    await result.current.signIn()
  })
  expect(result.current).toMatchObject({ busy: null, error: failure })
})
