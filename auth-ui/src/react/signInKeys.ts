import { useCallback, useEffect, useState } from "react"

import type { AuthKitError } from "../client/errors.ts"
import type { SignInKey } from "../client/types.ts"
import type { GuardOptions } from "./account.ts"
import { sessionIdentity, useAuthClient, useSession } from "./context.ts"
import { toAuthKitError, unguarded, useTask } from "./task.ts"

// The caller's passkeys and device keys: list, rename, revoke, and add a
// passkey. Renaming and revoking need a recent sign-in (pass guard).
export function useSignInKeys(options: GuardOptions = {}) {
  const client = useAuthClient()
  const guard = options.guard ?? unguarded
  const key = sessionIdentity(useSession())
  const authed = key.startsWith("authenticated:")
  const { busy, error, run } = useTask()
  const [nonce, setNonce] = useState(0)
  const request = `${key}|${nonce}`
  const [listed, setListed] = useState<{
    request: string
    keys: SignInKey[] | null
    error: AuthKitError | null
  } | null>(null)

  useEffect(() => {
    if (!authed) return
    const ctl = new AbortController()
    client.listSignInKeys(ctl.signal).then(
      (keys) => setListed({ request, keys, error: null }),
      (err: unknown) => {
        if (!ctl.signal.aborted)
          setListed({ request, keys: null, error: toAuthKitError(err) })
      }
    )
    return () => ctl.abort()
  }, [client, authed, request])

  const refetch = useCallback(() => setNonce((n) => n + 1), [])

  // Asks the browser for a new passkey; call from a click.
  const addPasskey = useCallback(
    () =>
      run(async () => {
        await client.registerPasskey()
        refetch()
      }),
    [client, run, refetch]
  )

  const rename = useCallback(
    (id: string, label: string) =>
      run(async () => {
        await guard(() => client.renameSignInKey(id, label.trim()))
        refetch()
      }),
    [client, guard, run, refetch]
  )

  const revoke = useCallback(
    (id: string) =>
      run(async () => {
        await guard(() => client.revokeSignInKey(id))
        refetch()
      }),
    [client, guard, run, refetch]
  )

  // Keep the previous list while a refetch for the same session runs.
  const usable = authed && listed?.request.startsWith(`${key}|`) ? listed : null
  return {
    keys: usable?.keys ?? null,
    loading: authed && listed?.request !== request,
    busy,
    // Action error first, then the listing error.
    error: error ?? usable?.error ?? null,
    refetch,
    addPasskey,
    rename,
    revoke,
  }
}
