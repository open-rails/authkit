import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react"

import type {
  AuthClient,
  AuthSession,
  RegistrationEvent,
} from "../client/client.ts"
import {
  AuthContext,
  createAuthContextValue,
  sessionIdentity,
} from "./context.ts"
import { sessionUser } from "./useAuth.ts"

const useStartEffect =
  typeof window === "undefined" ? useEffect : useLayoutEffect

export type AuthProviderProps = {
  client: AuthClient
  // Fires on sign-in, sign-out, expiry, user switch and same-user session
  // rotation (e.g. after proving an address), not on a silent refresh.
  onSessionChange?: (session: AuthSession, previous: AuthSession) => void
  // Fires only when the signed-in user changes (sign-in, sign-out, switch,
  // another tab): the host's hook to reset user data. A restore of the user
  // the session hint names is not a change.
  onUserChange?: (userId: string | null, previous: string | null) => void
  // A server-confirmed new account's completed sign-in. Credentials are
  // ready; this runs before onUserChange and other session subscribers.
  // Refreshes, restores and existing-account sign-ins never fire it.
  onRegistered?: (event: RegistrationEvent) => void
  // Call client.start() while mounted. Default true.
  autoStart?: boolean
  children?: ReactNode
}

export function AuthProvider({
  client,
  onSessionChange,
  onUserChange,
  onRegistered,
  autoStart = true,
  children,
}: AuthProviderProps) {
  const [value, setValue] = useState(() => createAuthContextValue(client))
  if (value.client !== client) setValue(createAuthContextValue(client))

  const onChange = useRef(onSessionChange)
  const onUser = useRef(onUserChange)
  const onRegistration = useRef(onRegistered)
  useEffect(() => {
    onChange.current = onSessionChange
    onUser.current = onUserChange
    onRegistration.current = onRegistered
  })

  useStartEffect(
    () => client.onRegistered((event) => onRegistration.current?.(event)),
    [client]
  )

  useEffect(() => {
    let previous = client.getSnapshot()
    let user = sessionUser(previous)
    return client.subscribe(() => {
      const next = client.getSnapshot()
      const nextUser = sessionUser(next)
      // A failed restore is a change from the hinted user; loading is not.
      if (next.status !== "loading" && nextUser !== user) {
        const before = user
        user = nextUser
        onUser.current?.(nextUser, before)
      }
      if (sessionIdentity(next) === sessionIdentity(previous)) {
        previous = next
        return
      }
      const before = previous
      previous = next
      onChange.current?.(next, before)
    })
  }, [client])

  // A layout effect runs before any child's passive effect, so requests the
  // tree makes on mount already wait for the restore (client.ready()).
  useStartEffect(
    () => (autoStart ? client.start() : undefined),
    [client, autoStart]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
