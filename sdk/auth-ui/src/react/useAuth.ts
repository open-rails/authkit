import { useState } from "react"

import type { AuthClient, AuthSession, SessionHint } from "../client/client.ts"
import type { UserProfile } from "../client/types.ts"
import { useAuthClient, useSession, useUser } from "./context.ts"

// "restoring": this browser was signed in (the session hint) and the cookie
// restore is under way; render the signed-in shell.
export type AuthStatus = "loading" | "restoring" | "signed_in" | "signed_out"

export type AuthState = {
  status: AuthStatus
  // signed_in or restoring.
  signedIn: boolean
  userId: string | null
  // GET /me; kept while the same user's session rotates and /me reloads.
  user: UserProfile | null
  // The persisted hint while restoring (userId, username).
  hint: SessionHint | null
  session: AuthSession
  // fetch for host APIs with the session bearer, refresh-and-retry and the
  // contact-proof retry.
  fetch: AuthClient["authFetch"]
  signOut: () => Promise<void>
}

// The user a session belongs to; a restoring session counts as its hint's
// user, so the restore of the same user is not a user change.
export function sessionUser(session: AuthSession): string | null {
  if (session.status === "authenticated") return session.userId
  if (session.status === "loading") return session.hint?.userId ?? null
  return null
}

export function authStatus(session: AuthSession): AuthStatus {
  switch (session.status) {
    case "authenticated":
      return "signed_in"
    case "anonymous":
      return "signed_out"
    default:
      return session.hint ? "restoring" : "loading"
  }
}

// The app's whole view of authentication.
export function useAuth(): AuthState {
  const client = useAuthClient()
  const session = useSession()
  const { user: loaded } = useUser()
  const [kept, setKept] = useState<UserProfile | null>(loaded)
  if (loaded && loaded !== kept) setKept(loaded)
  const userId = sessionUser(session)
  const status = authStatus(session)
  const user =
    loaded ??
    (session.status === "authenticated" && kept?.id === userId ? kept : null)
  return {
    status,
    signedIn: status === "signed_in" || status === "restoring",
    userId,
    user,
    hint: session.status === "loading" ? (session.hint ?? null) : null,
    session,
    fetch: client.authFetch,
    signOut: client.signOut,
  }
}
