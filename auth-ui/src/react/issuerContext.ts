import { createContext, useContext, useSyncExternalStore } from "react"

import type { AuthSession } from "../client/client.ts"
import type {
  IssuerClient,
  IssuerSignInOptions,
  IssuerUser,
} from "../client/issuer.ts"
import { authStatus, sessionUser, type AuthStatus } from "./useAuth.ts"

export const IssuerContext = createContext<IssuerClient | null>(null)

export function useIssuerClient(): IssuerClient {
  const client = useContext(IssuerContext)
  if (!client) throw new Error("auth-ui: wrap the tree in <IssuerAuthProvider>")
  return client
}

// useAuth's shape for an external issuer: the same session and status, the
// user from the issuer's ID token.
export type IssuerAuthState = {
  status: AuthStatus
  signedIn: boolean
  userId: string | null
  user: IssuerUser | null
  session: AuthSession
  fetch: IssuerClient["authFetch"]
  signIn: (opts?: IssuerSignInOptions) => Promise<void>
  stepUp: IssuerClient["stepUp"]
  signOut: IssuerClient["signOut"]
}

export function useIssuerAuth(): IssuerAuthState {
  const client = useIssuerClient()
  const session = useSyncExternalStore(
    client.subscribe,
    client.getSnapshot,
    client.getSnapshot
  )
  const status = authStatus(session)
  return {
    status,
    signedIn: status === "signed_in",
    userId: sessionUser(session),
    user: client.getUser(),
    session,
    fetch: client.authFetch,
    signIn: client.signIn,
    stepUp: client.stepUp,
    signOut: client.signOut,
  }
}
