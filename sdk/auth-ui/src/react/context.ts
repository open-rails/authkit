import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
} from "react"

import type { AuthClient, AuthSession } from "../client/client.ts"
import type { AuthKitError } from "../client/errors.ts"
import { hasPermission } from "../client/permissions.ts"
import type { Capabilities, UserProfile } from "../client/types.ts"
import { createResource, type Resource } from "./resource.ts"
import { toAuthKitError } from "./task.ts"

export type AuthContextValue = {
  client: AuthClient
  user: Resource<UserProfile>
  capabilities: Resource<Capabilities>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function createAuthContextValue(client: AuthClient): AuthContextValue {
  return {
    client,
    user: createResource((signal) => client.getMe(signal)),
    capabilities: createResource((signal) => client.getCapabilities(signal)),
  }
}

// Identity of a session: changes on sign-in, sign-out, expiry and user switch,
// not on a silent refresh.
export function sessionIdentity(session: AuthSession): string {
  if (session.status !== "authenticated") return session.status
  return `authenticated:${session.userId}:${String(session.claims.sid ?? "")}`
}

// Identity plus auth time: also changes after a step-up, whose fresher
// security state /me reports.
export function sessionGeneration(session: AuthSession): string | null {
  if (session.status !== "authenticated") return null
  const c = session.claims
  return `${sessionIdentity(session)}:${String(c.auth_time ?? "")}:${(c.amr ?? []).join(",")}`
}

function useAuthContext(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("auth-ui: wrap the tree in <AuthProvider>")
  return ctx
}

export const useAuthClient = (): AuthClient => useAuthContext().client

export function useSession(): AuthSession {
  const client = useAuthClient()
  return useSyncExternalStore(
    client.subscribe,
    client.getSnapshot,
    client.getSnapshot
  )
}

export type UserState = {
  user: UserProfile | null
  loading: boolean
  error: AuthKitError | null
  refetch: () => Promise<void>
}

// GET /me, shared across the tree and refetched per session generation.
export function useUser(): UserState {
  const { user } = useAuthContext()
  const key = sessionGeneration(useSession())
  useEffect(() => user.ensure(key), [user, key])
  const snap = useSyncExternalStore(
    user.subscribe,
    user.getSnapshot,
    user.getSnapshot
  )
  const current = key !== null && snap.key === key
  return {
    user: current ? snap.data : null,
    loading: key !== null && (!current || snap.loading),
    error: current ? snap.error : null,
    refetch: user.reload,
  }
}

export type CapabilitiesState = {
  capabilities: Capabilities | null
  loading: boolean
  error: AuthKitError | null
  refetch: () => Promise<void>
}

// GET /capabilities, fetched once per provider.
export function useCapabilities(): CapabilitiesState {
  const { capabilities } = useAuthContext()
  useEffect(() => capabilities.ensure("capabilities"), [capabilities])
  const snap = useSyncExternalStore(
    capabilities.subscribe,
    capabilities.getSnapshot,
    capabilities.getSnapshot
  )
  return {
    capabilities: snap.data,
    loading: snap.key === null || snap.loading,
    error: snap.error,
    refetch: capabilities.reload,
  }
}

export type PermissionsState = {
  permissions: string[] | null
  loading: boolean
  error: AuthKitError | null
  // Glob-aware (`root:*`), same semantics as AuthKit.
  has: (permission: string) => boolean
  refetch: () => void
}

// GET /me/permissions for a persona/instance, refetched per session.
export function usePermissions(
  scope: { persona?: string; instance?: string } = {}
): PermissionsState {
  const client = useAuthClient()
  const key = sessionIdentity(useSession())
  const authed = key.startsWith("authenticated:")
  const { persona, instance } = scope
  const [nonce, setNonce] = useState(0)
  const request = `${key}|${persona ?? ""}|${instance ?? ""}|${nonce}`
  const [state, setState] = useState<{
    request: string
    permissions: string[] | null
    error: AuthKitError | null
  } | null>(null)

  useEffect(() => {
    if (!authed) return
    const ctl = new AbortController()
    client.getPermissions({ persona, instance }, ctl.signal).then(
      (permissions) => setState({ request, permissions, error: null }),
      (err: unknown) => {
        if (!ctl.signal.aborted)
          setState({ request, permissions: null, error: toAuthKitError(err) })
      }
    )
    return () => ctl.abort()
  }, [client, authed, persona, instance, request])

  const current = authed && state?.request === request ? state : null
  const permissions = current?.permissions ?? null
  const has = useCallback(
    (permission: string) => hasPermission(permissions ?? undefined, permission),
    [permissions]
  )
  return {
    permissions,
    loading: authed && !current,
    error: current?.error ?? null,
    has,
    refetch: useCallback(() => setNonce((n) => n + 1), []),
  }
}
